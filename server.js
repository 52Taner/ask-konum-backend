const express = require("express");
const cors = require("cors");
const vaultRoutes =
  require('./vaultRoutes');
const mediaRoutes =
  require('./mediaRoutes');
const createSafePlaceRoutes =
  require('./safePlaceRoutes');
const {
  initializeApp,
  cert,
} = require("firebase-admin/app");

const {
  getFirestore,
} = require("firebase-admin/firestore");

const {
  getMessaging,
} = require("firebase-admin/messaging");

const {
  getAuth,
} = require("firebase-admin/auth");

// ============================================================
// APP
// ============================================================

const app = express();

// ============================================================
// MIDDLEWARE
// ============================================================

// JSON body'leri route'lardan önce oku.
app.use(
  express.json({
    limit: "1mb",
  })
);

const corsOptions = {
  origin: [
    "https://ask-konum.web.app",
    "https://ask-konum.firebaseapp.com",
    /^http:\/\/localhost:\d+$/,
    /^http:\/\/127\.0\.0\.1:\d+$/,
  ],

  methods: [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "OPTIONS",
  ],

  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "Accept",
  ],

  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// Preflight istekleri
app.options(
  "/send-notification",
  cors(corsOptions)
);

// Debug log
app.use((req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.path}`
  );

  next();
});

// ============================================================
// FIREBASE ADMIN
// ============================================================

const serviceAccount =
    require("/etc/secrets/serviceAccountKey.json");

initializeApp({
  credential: cert(serviceAccount),
  projectId: "ask-konum",
});

const db = getFirestore();

const safePlaceRoutes =
  createSafePlaceRoutes({ db });

// ============================================================
// TEST
// ============================================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message:
        "Aşk Konumu bildirim sunucusu çalışıyor ❤️",
  });
});

// Render Health Check için
app.get("/healthz", (req, res) => {
  res.status(200).json({
    success: true,
    status: "healthy",
  });
});

// ============================================================
// FIREBASE AUTH KONTROLÜ
// ============================================================

async function verifyFirebaseUser(
  req,
  res,
  next
) {
  try {
    const authorization =
        req.headers.authorization || "";

    if (
      !authorization.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        error:
            "Firebase kullanıcı tokenı bulunamadı.",
      });
    }

    const idToken =
        authorization.substring(7).trim();

    if (!idToken) {
      return res.status(401).json({
        success: false,
        error:
            "Firebase kullanıcı tokenı boş.",
      });
    }

    const decodedToken =
        await getAuth().verifyIdToken(
          idToken,
          true
        );

    const uid =
        (decodedToken.uid || "").trim();

    if (
      !uid ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(uid)
    ) {
      return res.status(403).json({
        success: false,
        error:
            "Geçersiz kullanıcı kimliği.",
      });
    }

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error(
      "AUTH HATASI:",
      error
    );

    return res.status(401).json({
      success: false,
      error:
          "Geçersiz kullanıcı oturumu.",
    });
  }
}

// ============================================================
// PUSH BİLDİRİM
// ============================================================

app.post(
  "/send-notification",
  verifyFirebaseUser,
  async (req, res) => {
    try {
      const senderId =
          req.user.uid;

      const {
        partnerId,
        title,
        body,
        type,
      } = req.body || {};

      // ------------------------------------------------------
      // REQUEST KONTROLÜ
      // ------------------------------------------------------

      if (
        !partnerId ||
        typeof partnerId !== "string"
      ) {
        return res.status(400).json({
          success: false,
          error:
              "partnerId bulunamadı.",
        });
      }

      // ------------------------------------------------------
      // GÖNDEREN KULLANICI
      // ------------------------------------------------------

      const senderDoc =
          await db
              .collection(
                "locations"
              )
              .doc(senderId)
              .get();

      if (!senderDoc.exists) {
        return res.status(404).json({
          success: false,
          error:
              "Gönderen kullanıcı bulunamadı.",
        });
      }

      const senderData =
          senderDoc.data() || {};

      // ------------------------------------------------------
      // PARTNER EŞLEŞME KONTROLÜ
      // ------------------------------------------------------

      if (
        senderData.partnerId !==
        partnerId
      ) {
        console.warn(
          "PARTNER YETKİ HATASI:",
          {
            senderId,
            expectedPartnerId:
                senderData.partnerId,
            requestedPartnerId:
                partnerId,
          }
        );

        return res.status(403).json({
          success: false,
          error:
              "Bu kullanıcıya bildirim gönderme yetkiniz yok.",
        });
      }

      // ------------------------------------------------------
      // PARTNER BELGESİ
      // ------------------------------------------------------

      const partnerDoc =
          await db
              .collection(
                "locations"
              )
              .doc(partnerId)
              .get();

      if (!partnerDoc.exists) {
        return res.status(404).json({
          success: false,
          error:
              "Partner bulunamadı.",
        });
      }

      const partnerData =
          partnerDoc.data() || {};

      if (
        partnerData.partnerId !==
        senderId
      ) {
        return res.status(403).json({
          success: false,
          error:
              "Karşılıklı partner eşleşmesi doğrulanamadı.",
        });
      }

      const fcmToken =
          partnerData.fcmToken;

      if (
        !fcmToken ||
        typeof fcmToken !== "string"
      ) {
        return res.status(404).json({
          success: false,
          error:
              "Partnerin FCM tokenı bulunamadı.",
        });
      }

      // ------------------------------------------------------
      // BİLDİRİM METNİ
      // ------------------------------------------------------

 const notificationTitle =
    typeof title === "string" &&
    title.trim().length > 0
        ? title.trim().substring(0, 100)
        : "Aşk Konumu ❤️";

const notificationBody =
    typeof body === "string" &&
    body.trim().length > 0
        ? body.trim().substring(0, 500)
        : "Yeni bir bildirimin var.";

const notificationType =
    typeof type === "string" &&
    type.trim().length > 0
        ? type.trim()
        : "general";

      // ------------------------------------------------------
      // FCM MESSAGE
      // ------------------------------------------------------

      const message = {
        token: fcmToken,

        notification: {
          title:
              notificationTitle,

          body:
              notificationBody,
        },

        data: {
          type:
              String(
                notificationType
              ),

          senderId:
              String(
                senderId
              ),

          partnerId:
              String(
                partnerId
              ),
        },

        webpush: {
          notification: {
            icon:
                "https://ask-konum.web.app/icons/Icon-192.png",

            badge:
                "https://ask-konum.web.app/icons/Icon-192.png",
          },

          fcmOptions: {
            link:
                "https://ask-konum.web.app/",
          },
        },
      };

      // ------------------------------------------------------
      // SEND
      // ------------------------------------------------------

      const messageId =
          await getMessaging()
              .send(message);

      console.log(
        "BİLDİRİM GÖNDERİLDİ:",
        messageId
      );

      return res.status(200).json({
        success: true,
        messageId,
      });
    } catch (error) {
      console.error(
        "BİLDİRİM HATASI:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
            "Bildirim gönderilemedi.",
      });
    }
  }
);

// ============================================================
// 404
// ============================================================
// Özel Kasa rotaları
app.use(
  '/api/vault',
  vaultRoutes,
);
app.use(
  '/api/media',
  mediaRoutes,
);
app.use(
  '/api/safe-places',
  verifyFirebaseUser,
  safePlaceRoutes,
);
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error:
        "Endpoint bulunamadı.",
  });
});

// ============================================================
// SERVER
// ============================================================

const PORT = process.env.PORT || 10000;

const server = app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Sunucu 0.0.0.0:${PORT} üzerinde çalışıyor`
    );
  }
);

server.keepAliveTimeout = 120000;
server.headersTimeout = 120000;
