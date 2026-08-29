const express = require("express");
const {
  FieldValue,
} = require("firebase-admin/firestore");
const {
  getMessaging,
} = require("firebase-admin/messaging");

const ALLOWED_PLACE_TYPES = new Set([
  "home",
  "work",
  "school",
]);

const PLACE_DETAILS = {
  home: {
    label: "Ev",
    emoji: "🏠",
    arrivalPhrase: "eve",
  },
  work: {
    label: "İş",
    emoji: "💼",
    arrivalPhrase: "iş yerine",
  },
  school: {
    label: "Okul",
    emoji: "🎓",
    arrivalPhrase: "okula",
  },
};

const MIN_RADIUS_METERS = 100;
const MAX_RADIUS_METERS = 500;
const DEFAULT_RADIUS_METERS = 150;
const EXIT_HYSTERESIS_METERS = 60;
const ARRIVAL_DWELL_MS = 20 * 1000;
const MAX_LOCATION_AGE_MS = 5 * 60 * 1000;
const MAX_PLACE_LABEL_LENGTH = 40;

function normalizePlaceLabel(value, placeType) {
  if (typeof value !== "string") {
    return PLACE_DETAILS[placeType].label;
  }

  const normalized = value
    .replace(/\s+/g, " ")
    .trim();

  return normalized || PLACE_DETAILS[placeType].label;
}

function isValidPlaceLabel(value) {
  if (typeof value !== "string") {
    return false;
  }

  const normalized = value
    .replace(/\s+/g, " ")
    .trim();

  return (
    normalized.length >= 1 &&
    normalized.length <= MAX_PLACE_LABEL_LENGTH
  );
}

function isFiniteNumber(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value)
  );
}

function isValidLatitude(value) {
  return (
    isFiniteNumber(value) &&
    value >= -90 &&
    value <= 90
  );
}

function isValidLongitude(value) {
  return (
    isFiniteNumber(value) &&
    value >= -180 &&
    value <= 180
  );
}

function normalizeRadius(value) {
  if (!isFiniteNumber(value)) {
    return DEFAULT_RADIUS_METERS;
  }

  return Math.min(
    MAX_RADIUS_METERS,
    Math.max(
      MIN_RADIUS_METERS,
      Math.round(value)
    )
  );
}

function toRadians(value) {
  return value * (Math.PI / 180);
}

function distanceBetweenMeters(
  latitude1,
  longitude1,
  latitude2,
  longitude2
) {
  const earthRadiusMeters = 6371000;
  const latitudeDelta = toRadians(
    latitude2 - latitude1
  );
  const longitudeDelta = toRadians(
    longitude2 - longitude1
  );

  const startLatitude = toRadians(
    latitude1
  );
  const endLatitude = toRadians(
    latitude2
  );

  const haversine =
    Math.sin(latitudeDelta / 2) ** 2 +
    Math.cos(startLatitude) *
      Math.cos(endLatitude) *
      Math.sin(longitudeDelta / 2) ** 2;

  return (
    2 *
    earthRadiusMeters *
    Math.asin(
      Math.min(1, Math.sqrt(haversine))
    )
  );
}

function timestampToMillis(value) {
  if (
    value &&
    typeof value.toMillis === "function"
  ) {
    return value.toMillis();
  }

  return null;
}

function cleanPlaces(rawPlaces) {
  if (
    rawPlaces === null ||
    typeof rawPlaces !== "object" ||
    Array.isArray(rawPlaces)
  ) {
    return {};
  }

  const places = {};

  for (const placeType of ALLOWED_PLACE_TYPES) {
    const rawPlace = rawPlaces[placeType];

    if (
      rawPlace === null ||
      typeof rawPlace !== "object" ||
      Array.isArray(rawPlace)
    ) {
      continue;
    }

    const latitude = rawPlace.latitude;
    const longitude = rawPlace.longitude;

    if (
      !isValidLatitude(latitude) ||
      !isValidLongitude(longitude)
    ) {
      continue;
    }

    places[placeType] = {
      latitude,
      longitude,
      label: normalizePlaceLabel(
        rawPlace.label,
        placeType
      ),
      emoji: PLACE_DETAILS[placeType].emoji,
    };
  }

  return places;
}

function cleanPlaceNotifications(rawNotifications) {
  const notifications = {};
  const source =
    rawNotifications !== null &&
    typeof rawNotifications === "object" &&
    !Array.isArray(rawNotifications)
      ? rawNotifications
      : {};

  for (const placeType of ALLOWED_PLACE_TYPES) {
    notifications[placeType] =
      source[placeType] !== false;
  }

  return notifications;
}

function createSafePlaceRoutes({ db }) {
  if (!db) {
    throw new Error(
      "Safe place routes için Firestore gerekli."
    );
  }

  const router = express.Router();

  function safePlaceRef(uid) {
    return db
      .collection("private_safe_places")
      .doc(uid);
  }

  router.get("/", async (req, res) => {
    try {
      const uid = req.user.uid;
      const snapshot =
        await safePlaceRef(uid).get();
      const data = snapshot.data() || {};

      return res.status(200).json({
        success: true,
        enabled: data.enabled === true,
        radiusMeters: normalizeRadius(
          data.radiusMeters
        ),
        placeNotifications:
          cleanPlaceNotifications(
            data.placeNotifications
          ),
        places: cleanPlaces(data.places),
      });
    } catch (error) {
      console.error(
        "YERLERİ GETİRME HATASI:",
        error
      );

      return res.status(500).json({
        success: false,
        error: "Kayıtlı yerler alınamadı.",
      });
    }
  });

  router.put("/settings", async (req, res) => {
    try {
      const uid = req.user.uid;
      const {
        enabled,
        radiusMeters,
        placeNotifications,
      } =
        req.body || {};

      if (typeof enabled !== "boolean") {
        return res.status(400).json({
          success: false,
          error: "enabled alanı boolean olmalı.",
        });
      }

      if (
        !isFiniteNumber(radiusMeters) ||
        radiusMeters < MIN_RADIUS_METERS ||
        radiusMeters > MAX_RADIUS_METERS
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Yarıçap 100 ile 500 metre arasında olmalı.",
        });
      }

      const normalizedRadius =
        normalizeRadius(radiusMeters);
      const normalizedPlaceNotifications =
        cleanPlaceNotifications(
          placeNotifications
        );

      await db.runTransaction(
        async (transaction) => {
          const reference = safePlaceRef(uid);
          const snapshot =
            await transaction.get(reference);
          const data = snapshot.data() || {};

          transaction.set(
            reference,
            {
              ownerId: uid,
              enabled,
              radiusMeters: normalizedRadius,
              placeNotifications:
                normalizedPlaceNotifications,
              places: cleanPlaces(data.places),
              insideStates: {},
              candidateSinceMs: {},
              updatedAt:
                FieldValue.serverTimestamp(),
            },
            { merge: true }
          );
        }
      );

      return res.status(200).json({
        success: true,
        enabled,
        radiusMeters: normalizedRadius,
        placeNotifications:
          normalizedPlaceNotifications,
      });
    } catch (error) {
      console.error(
        "YER AYARLARI HATASI:",
        error
      );

      return res.status(500).json({
        success: false,
        error: "Yer ayarları kaydedilemedi.",
      });
    }
  });

  router.put("/:placeType", async (req, res) => {
    try {
      const uid = req.user.uid;
      const placeType = req.params.placeType;

      if (!ALLOWED_PLACE_TYPES.has(placeType)) {
        return res.status(400).json({
          success: false,
          error: "Geçersiz yer türü.",
        });
      }

      const { latitude, longitude, label } =
        req.body || {};

      if (
        !isValidLatitude(latitude) ||
        !isValidLongitude(longitude)
      ) {
        return res.status(400).json({
          success: false,
          error: "Geçersiz konum koordinatı.",
        });
      }

      if (
        label !== undefined &&
        !isValidPlaceLabel(label)
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Konum adı 1 ile 40 karakter arasında olmalı.",
        });
      }

      const normalizedLabel =
        normalizePlaceLabel(label, placeType);

      const reference = safePlaceRef(uid);

      await db.runTransaction(
        async (transaction) => {
          const snapshot =
            await transaction.get(reference);
          const data = snapshot.data() || {};
          const places = cleanPlaces(data.places);
          const insideStates = {
            ...(data.insideStates || {}),
          };
          const candidateSinceMs = {
            ...(data.candidateSinceMs || {}),
          };

          places[placeType] = {
            latitude,
            longitude,
            label: normalizedLabel,
            emoji: PLACE_DETAILS[placeType].emoji,
          };

          delete insideStates[placeType];
          delete candidateSinceMs[placeType];

          transaction.set(
            reference,
            {
              ownerId: uid,
              places,
              insideStates,
              candidateSinceMs,
              updatedAt:
                FieldValue.serverTimestamp(),
            },
            { merge: true }
          );
        }
      );

      return res.status(200).json({
        success: true,
        placeType,
        place: {
          latitude,
          longitude,
          label: normalizedLabel,
          emoji: PLACE_DETAILS[placeType].emoji,
        },
      });
    } catch (error) {
      console.error(
        "YER KAYDETME HATASI:",
        error
      );

      return res.status(500).json({
        success: false,
        error: "Yer kaydedilemedi.",
      });
    }
  });

  router.delete(
    "/:placeType",
    async (req, res) => {
      try {
        const uid = req.user.uid;
        const placeType =
          req.params.placeType;

        if (!ALLOWED_PLACE_TYPES.has(placeType)) {
          return res.status(400).json({
            success: false,
            error: "Geçersiz yer türü.",
          });
        }

        const reference = safePlaceRef(uid);

        await db.runTransaction(
          async (transaction) => {
            const snapshot =
              await transaction.get(reference);
            const data = snapshot.data() || {};
            const places =
              cleanPlaces(data.places);
            const insideStates = {
              ...(data.insideStates || {}),
            };
            const candidateSinceMs = {
              ...(data.candidateSinceMs || {}),
            };

            delete places[placeType];
            delete insideStates[placeType];
            delete candidateSinceMs[placeType];

            transaction.set(
              reference,
              {
                ownerId: uid,
                places,
                insideStates,
                candidateSinceMs,
                updatedAt:
                  FieldValue.serverTimestamp(),
              },
              { merge: true }
            );
          }
        );

        return res.status(200).json({
          success: true,
          placeType,
        });
      } catch (error) {
        console.error(
          "YER SİLME HATASI:",
          error
        );

        return res.status(500).json({
          success: false,
          error: "Yer silinemedi.",
        });
      }
    }
  );

  router.post("/check", async (req, res) => {
    try {
      const uid = req.user.uid;
      const senderReference = db
        .collection("locations")
        .doc(uid);
      const senderSnapshot =
        await senderReference.get();

      if (!senderSnapshot.exists) {
        return res.status(404).json({
          success: false,
          error: "Kullanıcı konumu bulunamadı.",
        });
      }

      const senderData =
        senderSnapshot.data() || {};
      const partnerId =
        typeof senderData.partnerId === "string"
          ? senderData.partnerId.trim()
          : "";

      if (!partnerId) {
        return res.status(409).json({
          success: false,
          error: "Partner eşleşmesi bulunamadı.",
        });
      }

      const latitude = senderData.latitude;
      const longitude = senderData.longitude;

      if (
        !isValidLatitude(latitude) ||
        !isValidLongitude(longitude)
      ) {
        return res.status(409).json({
          success: false,
          error: "Güncel konum bulunamadı.",
        });
      }

      const locationUpdatedAt =
        timestampToMillis(
          senderData.updatedAt
        ) ||
        timestampToMillis(
          senderData.backgroundUpdatedAt
        );

      if (
        locationUpdatedAt === null ||
        Date.now() - locationUpdatedAt >
          MAX_LOCATION_AGE_MS
      ) {
        return res.status(409).json({
          success: false,
          error: "Konum bilgisi güncel değil.",
        });
      }

      const partnerSnapshot = await db
        .collection("locations")
        .doc(partnerId)
        .get();
      const partnerData =
        partnerSnapshot.data() || {};

      if (
        !partnerSnapshot.exists ||
        partnerData.partnerId !== uid
      ) {
        return res.status(403).json({
          success: false,
          error:
            "Karşılıklı partner eşleşmesi doğrulanamadı.",
        });
      }

      const fcmToken =
        typeof partnerData.fcmToken === "string"
          ? partnerData.fcmToken.trim()
          : "";

      if (!fcmToken) {
        return res.status(409).json({
          success: false,
          error:
            "Partnerin bildirim kaydı bulunamadı.",
        });
      }

      const now = Date.now();
      const reference = safePlaceRef(uid);

      const result = await db.runTransaction(
        async (transaction) => {
          const snapshot =
            await transaction.get(reference);

          if (!snapshot.exists) {
            return {
              enabled: false,
              arrival: null,
            };
          }

          const data = snapshot.data() || {};
          const enabled = data.enabled === true;
          const places = cleanPlaces(data.places);
          const placeNotifications =
            cleanPlaceNotifications(
              data.placeNotifications
            );

          if (!enabled || !Object.keys(places).length) {
            return {
              enabled,
              arrival: null,
            };
          }

          const radiusMeters = normalizeRadius(
            data.radiusMeters
          );
          const insideStates = {
            ...(data.insideStates || {}),
          };
          const candidateSinceMs = {
            ...(data.candidateSinceMs || {}),
          };
          let arrival = null;
          let arrivalLabel = null;

          for (const placeType of [
            "home",
            "work",
            "school",
          ]) {
            const place = places[placeType];

            if (
              !place ||
              !placeNotifications[placeType]
            ) {
              continue;
            }

            const previousState =
              typeof insideStates[placeType] ===
              "boolean"
                ? insideStates[placeType]
                : null;
            const distance =
              distanceBetweenMeters(
                latitude,
                longitude,
                place.latitude,
                place.longitude
              );
            const effectiveRadius =
              previousState === true
                ? radiusMeters +
                  EXIT_HYSTERESIS_METERS
                : radiusMeters;
            const isInside =
              distance <= effectiveRadius;

            if (previousState === null) {
              insideStates[placeType] =
                isInside;
              delete candidateSinceMs[placeType];
              continue;
            }

            if (previousState && !isInside) {
              insideStates[placeType] = false;
              delete candidateSinceMs[placeType];
              continue;
            }

            if (previousState || !isInside) {
              delete candidateSinceMs[placeType];
              continue;
            }

            const candidateSince =
              Number(candidateSinceMs[placeType]);

            if (!Number.isFinite(candidateSince)) {
              candidateSinceMs[placeType] = now;
              continue;
            }

            if (
              now - candidateSince <
              ARRIVAL_DWELL_MS
            ) {
              continue;
            }

            insideStates[placeType] = true;
            delete candidateSinceMs[placeType];

            if (arrival === null) {
              arrival = placeType;
              arrivalLabel = place.label;
            }
          }

          transaction.set(
            reference,
            {
              ownerId: uid,
              insideStates,
              candidateSinceMs,
              lastCheckedAt:
                FieldValue.serverTimestamp(),
              updatedAt:
                FieldValue.serverTimestamp(),
            },
            { merge: true }
          );

          return {
            enabled: true,
            arrival,
            arrivalLabel,
          };
        }
      );

      if (!result.arrival) {
        return res.status(200).json({
          success: true,
          enabled: result.enabled,
          notificationSent: false,
        });
      }

      const placeDetails =
        PLACE_DETAILS[result.arrival];
      const arrivalLabel =
        result.arrivalLabel ||
        placeDetails.label;

      const messageId = await getMessaging().send({
        token: fcmToken,
        notification: {
          title:
            `Varış Bildirimi ${placeDetails.emoji}`,
          body:
            `Partnerin “${arrivalLabel}” konumuna vardı.`,
        },
        data: {
          type: "safe_place_arrival",
          senderId: uid,
          partnerId,
          placeType: result.arrival,
          placeLabel: arrivalLabel,
        },
        webpush: {
          notification: {
            icon:
              "https://ask-konum.web.app/icons/Icon-192.png",
            badge:
              "https://ask-konum.web.app/icons/Icon-192.png",
          },
          fcmOptions: {
            link: "https://ask-konum.web.app/",
          },
        },
      });

      console.log(
        "VARIŞ BİLDİRİMİ GÖNDERİLDİ:",
        {
          uid,
          partnerId,
          placeType: result.arrival,
          messageId,
        }
      );

      return res.status(200).json({
        success: true,
        enabled: true,
        notificationSent: true,
        placeType: result.arrival,
      });
    } catch (error) {
      console.error(
        "YER VARIŞ KONTROLÜ HATASI:",
        error
      );

      return res.status(500).json({
        success: false,
        error: "Varış kontrolü yapılamadı.",
      });
    }
  });

  return router;
}

module.exports = createSafePlaceRoutes;
