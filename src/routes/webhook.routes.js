const express = require("express");
const crypto = require("crypto");
const supabase = require("../config/supabase");

const router = express.Router();

/**
 * Normalizes priority/severity string to allowed enum values:
 * 'low' | 'medium' | 'high' | 'critical'
 */
function normalizeSeverity(val) {
  if (!val) return "low";

  const str = String(val).toLowerCase();

  if (str === "urgent" || str === "critical") {
    return "critical";
  }

  if (str === "high") {
    return "high";
  }

  if (str === "medium" || str === "normal") {
    return "medium";
  }

  return "low";
}

/**
 * Get webhook secret for each external service.
 *
 * Add more services here in the future.
 */
function getWebhookSecret(serviceName) {
  const secrets = {
    jobboard: process.env.JOBBOARD_WEBHOOK_SECRET,
    system2: process.env.SYSTEM2_WEBHOOK_SECRET,
  };

  return secrets[String(serviceName).toLowerCase()];
}

/**
 * Safely compare two secret strings.
 */
function compareSecrets(receivedSecret, expectedSecret) {
  try {
    const receivedBuffer = Buffer.from(
      String(receivedSecret),
      "utf8"
    );

    const expectedBuffer = Buffer.from(
      String(expectedSecret),
      "utf8"
    );

    if (receivedBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      receivedBuffer,
      expectedBuffer
    );
  } catch (error) {
    return false;
  }
}

/**
 * Handles incoming webhook events
 * for a given external service.
 */
async function handleServiceWebhook(
  serviceName,
  req,
  res
) {
  try {
    const body = req.body || {};

    /*
     * =========================================
     * WEBHOOK AUTHENTICATION
     * =========================================
     */

    const expectedSecret =
      getWebhookSecret(serviceName);

    // Check whether this service has
    // a secret configured in Render/.env
    if (!expectedSecret) {
      console.error(
        `[WEBHOOK] No secret configured for service: ${serviceName}`
      );

      return res.status(403).json({
        error: "Webhook service is not configured",
        service: serviceName,
      });
    }

    // External service must send:
    //
    // X-Webhook-Secret: xxxxxxxx
    //
    const receivedSecret =
      req.headers["x-webhook-secret"];

    if (!receivedSecret) {
      console.warn(
        `[WEBHOOK] Missing secret from ${serviceName}`
      );

      return res.status(401).json({
        error: "Missing webhook secret",
      });
    }

    const secretValid = compareSecrets(
      receivedSecret,
      expectedSecret
    );

    if (!secretValid) {
      console.warn(
        `[WEBHOOK] Invalid secret from ${serviceName}`
      );

      return res.status(401).json({
        error: "Invalid webhook secret",
      });
    }

    console.log(
      `[WEBHOOK] Authenticated request from ${serviceName}`
    );

    /*
     * =========================================
     * FLEXIBLE FIELD MAPPING
     * =========================================
     */

    const eventId =
      body.eventId ||
      body.event_id ||
      body.id ||
      `${serviceName}-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 7)}`;

    const eventType =
      body.eventType ||
      body.event_type ||
      body.event ||
      body.type ||
      `${serviceName}.notification`;

    const userId =
      body.userId ||
      body.user_id ||
      body.recipientId ||
      body.recipient_id ||
      body.studentId ||
      body.student_id;

    const title =
      body.title ||
      body.subject ||
      `New update from ${serviceName}`;

    const message =
      body.message ||
      body.description ||
      body.content ||
      body.body;

    /*
     * =========================================
     * VALIDATION
     * =========================================
     */

    if (!userId) {
      return res.status(400).json({
        error:
          "userId is required in webhook payload",
      });
    }

    if (!message) {
      return res.status(400).json({
        error:
          "message (or description/content) is required in webhook payload",
      });
    }

    const severity = normalizeSeverity(
      body.severity || body.priority
    );

    const deadline =
      body.deadline || null;

    const metadata =
      body.metadata ||
      body.data ||
      body.payload ||
      {};

    /*
     * =========================================
     * CHECK DUPLICATE EVENT
     * =========================================
     */

    if (
      body.eventId ||
      body.event_id ||
      body.id
    ) {
      const {
        data: existingEvent,
        error: checkError,
      } = await supabase
        .from("event_receipts")
        .select("id, event_id, status")
        .eq("event_id", eventId)
        .maybeSingle();

      if (checkError) {
        console.error(
          "Failed to check duplicate event:",
          checkError
        );
      } else if (existingEvent) {
        return res.status(200).json({
          status: "duplicate",
          service: serviceName,
          eventReceiptId:
            existingEvent.id,
          eventId:
            existingEvent.event_id,
        });
      }
    }

    /*
     * =========================================
     * CREATE EVENT RECEIPT
     * =========================================
     */

    const {
      data: eventReceipt,
      error: receiptError,
    } = await supabase
      .from("event_receipts")
      .insert({
        event_id: eventId,
        event_type: eventType,
        source_service: serviceName,
        payload: body,

        // Do NOT store webhook secret
        // in the database.
        signature: null,

        status: "accepted",
      })
      .select()
      .single();

    if (receiptError) {
      console.error(
        "Failed to record event receipt:",
        receiptError
      );

      return res.status(500).json({
        error:
          "Failed to record event receipt",
      });
    }

    /*
     * =========================================
     * GET USER PREFERENCES
     * =========================================
     */

    const {
      data: preference,
      error: preferenceError,
    } = await supabase
      .from("preferences")
      .select(
        "in_app_enabled, email_enabled"
      )
      .eq("user_id", userId)
      .maybeSingle();

    if (preferenceError) {
      console.error(
        "Failed to get preferences:",
        preferenceError
      );
    }

    const inAppEnabled =
      preference?.in_app_enabled ?? true;

    const emailEnabled =
      preference?.email_enabled ?? false;

    /*
     * =========================================
     * CREATE NOTIFICATION
     * =========================================
     */

    const {
      data: notification,
      error: notifError,
    } = await supabase
      .from("notifications")
      .insert({
        user_id: userId,
        event_receipt_id:
          eventReceipt.id,
        title,
        message,
        severity,
        deadline,

        metadata: {
          ...metadata,
          source_service: serviceName,
          event_type: eventType,
        },
      })
      .select()
      .single();

    if (notifError) {
      console.error(
        "Failed to create notification from webhook:",
        notifError
      );

      return res.status(500).json({
        error:
          "Failed to create notification",
      });
    }

    /*
     * =========================================
     * CREATE DELIVERIES
     * =========================================
     */

    const deliveriesToCreate = [];

    if (inAppEnabled) {
      deliveriesToCreate.push({
        notification_id:
          notification.id,
        channel: "in_app",
        status: "pending",
        attempt_count: 0,
      });
    }

    if (emailEnabled) {
      deliveriesToCreate.push({
        notification_id:
          notification.id,
        channel: "email",
        status: "pending",
        attempt_count: 0,
      });
    }

    let createdDeliveries = [];

    if (
      deliveriesToCreate.length > 0
    ) {
      const {
        data: deliveryData,
        error: deliveryError,
      } = await supabase
        .from("deliveries")
        .insert(
          deliveriesToCreate
        )
        .select();

      if (deliveryError) {
        console.error(
          "Failed to create deliveries:",
          deliveryError
        );
      } else {
        createdDeliveries =
          deliveryData || [];
      }
    }

    /*
     * =========================================
     * SUCCESS RESPONSE
     * =========================================
     */

    return res.status(201).json({
      status: "accepted",
      service: serviceName,

      eventReceiptId:
        eventReceipt.id,

      notificationId:
        notification.id,

      notification,

      deliveries:
        createdDeliveries,
    });
  } catch (error) {
    console.error(
      `Unexpected webhook error for ${serviceName}:`,
      error
    );

    return res.status(500).json({
      error:
        "Internal server error processing webhook",
    });
  }
}

/*
 * =========================================
 * ROUTES
 * =========================================
 */

// Job Board
//
// POST /api/webhooks/jobboard
//
router.post(
  "/jobboard",
  async (req, res) => {
    return handleServiceWebhook(
      "JobBoard",
      req,
      res
    );
  }
);

// Other partner systems
//
// Example:
// POST /api/webhooks/system2
// POST /api/webhooks/internship
// POST /api/webhooks/alumni
//
router.post(
  "/:service",
  async (req, res) => {
    const serviceName =
      req.params.service;

    return handleServiceWebhook(
      serviceName,
      req,
      res
    );
  }
);

module.exports = router;