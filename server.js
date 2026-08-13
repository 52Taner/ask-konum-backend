const express = require("express");
const cors = require("cors");

const app = express();

// JSON body'leri okuyabilmek için
app.use(express.json());

const {
  initializeApp,
  applicationDefault,
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
// FIREBASE ADMIN
// ============================================================

initializeApp({
  credential: applicationDefault(),
  projectId: "ask-konum",
});

const db = getFirestore();



// ============================================================
// MIDDLEWARE
// ============================================================

const corsOptions = {
  origin: [
    "https://ask-konum.web.app",
    "https://ask-konum.firebaseapp.com",
    "http://localhost:5000",
  ],
  methods: [
    "GET",
    "POST",
    "OPTIONS",
  ],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
  ],
};

app.use(cors(corsOptions));

app.options(
  "/send-notification",
  cors(corsOptions)
);

// ============================================================
// TEST
// ============================================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Aşk Konumu bildirim sunucusu çalışıyor ❤️",
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
      !authorization.startsWith(
        "Bearer "
      )
    ) {
      return res.status(401).json({
        success: false,
        error:
            "Firebase kullanıcı tokenı bulunamadı.",
      });
    }

    const idToken =
      authorization.substring(7);

    const decodedToken =
      await getAuth().verifyIdToken(
        idToken
      );

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
      } = req.body;

      // ------------------------------------------------------
      // KONTROL
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
      // GÖNDEREN KULLANICININ PARTNERİNİ KONTROL ET
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
          senderDoc.data();

      if (
        senderData.partnerId !==
        partnerId
      ) {
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
          partnerDoc.data();

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
      // BİLDİRİM
      // ------------------------------------------------------

      const notificationTitle =
          title ||
          "Aşk Konumu ❤️";

      const notificationBody =
          body ||
          "Yeni bir bildirimin var.";

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
                type ||
                "general"
              ),

          senderId:
              String(senderId),

          partnerId:
              String(partnerId),
        },

        webpush: {
          notification: {
            icon:
                "/icons/Icon-192.png",

            badge:
                "/icons/Icon-192.png",
          },

          fcmOptions: {
            link:
                "https://ask-konum.web.app/",
          },
        },
      };

      const messageId =
          await getMessaging()
              .send(message);

      console.log(
        "BİLDİRİM GÖNDERİLDİ:",
        messageId
      );

      return res.json({
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
            error.message ||
            "Bildirim gönderilemedi.",
      });
    }
  }
);

// ============================================================
// SERVER
// ============================================================

const PORT =
    process.env.PORT || 3000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "❤️ Aşk Konumu Backend"
    );

    console.log(
      `🚀 Sunucu çalışıyor: ${PORT}`
    );
  }
);