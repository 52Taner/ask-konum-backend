const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');
const { getAuth } = require("firebase-admin/auth");

const {
  createClient,
} = require('@supabase/supabase-js');

const router = express.Router();

const supabaseUrl =
  (process.env.SUPABASE_URL || '').trim();

const supabaseSecretKey =
  (
    process.env.SUPABASE_SECRET_KEY ||
    ''
  ).trim();

const vaultBucket =
  (
    process.env.SUPABASE_VAULT_BUCKET ||
    'private-vault'
  ).trim();

if (!supabaseUrl) {
  throw new Error(
    'SUPABASE_URL ortam değişkeni eksik.',
  );
}

if (!supabaseSecretKey) {
  throw new Error(
    'SUPABASE_SECRET_KEY ortam değişkeni eksik.',
  );
}

const supabaseAdmin = createClient(
  supabaseUrl,
  supabaseSecretKey,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  },
);

// ============================================================
// FIREBASE KULLANICISINI DOĞRULA
// ============================================================

async function verifyFirebaseUser(
  req,
  res,
  next,
) {
  try {
    const authorization =
      req.get('authorization') || '';

    if (
      !authorization.startsWith(
        'Bearer ',
      )
    ) {
      return res.status(401).json({
        error:
          'Kimlik doğrulama bilgisi eksik.',
      });
    }

    const idToken =
      authorization
        .substring(7)
        .trim();

    if (!idToken) {
      return res.status(401).json({
        error:
          'Firebase kimlik jetonu eksik.',
      });
    }

    // true: iptal edilmiş oturumları da kontrol eder.
    const decodedToken =
    await getAuth().verifyIdToken(idToken);

    const uid =
      (decodedToken.uid || '').trim();

    if (
      !uid ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(uid)
    ) {
      return res.status(403).json({
        error:
          'Geçersiz kullanıcı kimliği.',
      });
    }

    req.firebaseUser = decodedToken;

    return next();
  } catch (error) {
    console.error(
      'Vault kimlik doğrulama hatası:',
      error.message,
    );

    return res.status(401).json({
      error:
        'Oturum geçersiz veya süresi dolmuş.',
    });
  }
}
// ============================================================
// BASE64URL DOĞRULAMA
// ============================================================

function decodeBase64Url(
  value,
) {
  try {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.length > 500 ||
      !/^[A-Za-z0-9_-]+={0,2}$/.test(
        value,
      )
    ) {
      return null;
    }

    const decoded =
      Buffer.from(
        value,
        'base64url',
      );

    if (decoded.length === 0) {
      return null;
    }

    return decoded;
  } catch (_) {
    return null;
  }
}

// ============================================================
// KASA ANAHTAR ZARFINI KAYDET
// PUT /api/vault/key-envelope
// ============================================================

router.put(
  '/key-envelope',
  verifyFirebaseUser,
  async (req, res) => {
    try {
      const uid =
        req.firebaseUser.uid;

      const {
        version,
        iterations,
        salt,
        wrappedKey,
      } = req.body || {};

      if (version !== 1) {
        return res.status(400).json({
          error:
            'Geçersiz kasa sürümü.',
        });
      }

      if (
        !Number.isInteger(
          iterations,
        ) ||
        iterations < 100000 ||
        iterations > 2000000
      ) {
        return res.status(400).json({
          error:
            'Geçersiz parola güvenlik ayarı.',
        });
      }

      const saltBytes =
        decodeBase64Url(salt);

      const wrappedKeyBytes =
        decodeBase64Url(
          wrappedKey,
        );

      // 16 byte rastgele salt
      if (
        saltBytes == null ||
        saltBytes.length !== 16
      ) {
        return res.status(400).json({
          error:
            'Geçersiz kasa salt değeri.',
        });
      }

      // AES-GCM:
      // 12 byte nonce + 32 byte anahtar + 16 byte MAC
      if (
        wrappedKeyBytes == null ||
        wrappedKeyBytes.length !== 60
      ) {
        return res.status(400).json({
          error:
            'Geçersiz şifrelenmiş kasa anahtarı.',
        });
      }

      const configRef =
        admin
          .firestore()
          .collection(
            'private_vault_configs',
          )
          .doc(uid);

      const oldDocument =
        await configRef.get();

      const documentData = {
        ownerId: uid,
        version,
        iterations,
        salt,
        wrappedKey,
        updatedAt:
          admin.firestore
            .FieldValue
            .serverTimestamp(),
      };

      if (!oldDocument.exists) {
        documentData.createdAt =
          admin.firestore
            .FieldValue
            .serverTimestamp();
      }

      await configRef.set(
        documentData,
        {
          merge: true,
        },
      );

      res.set(
        'Cache-Control',
        'no-store',
      );

      return res.status(
        oldDocument.exists
          ? 200
          : 201,
      ).json({
        success: true,
      });
    } catch (error) {
      console.error(
        'Kasa anahtar kaydetme hatası:',
        error.message,
      );

      return res.status(500).json({
        error:
          'Kasa anahtar bilgisi kaydedilemedi.',
      });
    }
  },
);

// ============================================================
// KASA ANAHTAR ZARFINI GETİR
// GET /api/vault/key-envelope
// ============================================================

router.get(
  '/key-envelope',
  verifyFirebaseUser,
  async (req, res) => {
    try {
      const uid =
        req.firebaseUser.uid;

      const document =
        await admin
          .firestore()
          .collection(
            'private_vault_configs',
          )
          .doc(uid)
          .get();

      res.set(
        'Cache-Control',
        'no-store',
      );

      if (!document.exists) {
        return res.status(404).json({
          error:
            'Kasa anahtarı henüz oluşturulmamış.',
        });
      }

      const data =
        document.data() || {};

      return res.status(200).json({
        version: data.version,
        iterations:
          data.iterations,
        salt: data.salt,
        wrappedKey:
          data.wrappedKey,
      });
    } catch (error) {
      console.error(
        'Kasa anahtar okuma hatası:',
        error.message,
      );

      return res.status(500).json({
        error:
          'Kasa anahtar bilgisi alınamadı.',
      });
    }
  },
);
// ============================================================
// ŞİFRELİ FOTOĞRAF YÜKLE
// POST /api/vault/upload
// ============================================================

router.post(
  '/upload',

  verifyFirebaseUser,

  express.raw({
    type: 'application/octet-stream',
    limit: '15mb',
  }),

  async (req, res) => {
    try {
      const encryptedBytes =
        req.body;

      if (
        !Buffer.isBuffer(
          encryptedBytes,
        ) ||
        encryptedBytes.length === 0
      ) {
        return res.status(400).json({
          error:
            'Şifreli dosya verisi bulunamadı.',
        });
      }

      const uid =
        req.firebaseUser.uid;

      const fileId =
        crypto.randomUUID();

      // Kullanıcı, dosya yolunu kendisi belirleyemez.
      // Yol her zaman doğrulanan Firebase UID'sinden oluşur.
      const storagePath =
        `${uid}/${fileId}.vault`;

      const {
        data,
        error,
      } = await supabaseAdmin
        .storage
        .from(vaultBucket)
        .upload(
          storagePath,
          encryptedBytes,
          {
            contentType:
              'application/octet-stream',
            cacheControl: '0',
            upsert: false,
          },
        );

      if (error) {
        console.error(
          'Supabase vault yükleme hatası:',
          error.message,
        );

        return res.status(500).json({
          error:
            'Şifreli dosya kaydedilemedi.',
        });
      }

      return res.status(201).json({
        success: true,
        fileId,
        storagePath:
          data.path,
        encryptedSize:
          encryptedBytes.length,
      });
    } catch (error) {
      console.error(
        'Vault yükleme hatası:',
        error.message,
      );

      return res.status(500).json({
        error:
          'Kasa yükleme işlemi başarısız.',
      });
    }
  },
);

// ============================================================
// DOSYA BOYUTU HATASI
// ============================================================

router.use(
  (
    error,
    req,
    res,
    next,
  ) => {
    if (
      error?.type ===
      'entity.too.large'
    ) {
      return res.status(413).json({
        error:
          'Şifreli dosyanın boyutu 15 MB sınırını aşıyor.',
      });
    }

    return next(error);
  },
);

module.exports = router;