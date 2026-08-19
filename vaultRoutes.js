const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');

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
      await admin
        .auth()
        .verifyIdToken(
          idToken,
          true,
        );

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