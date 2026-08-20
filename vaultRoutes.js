const express = require('express');

const { getAuth } = require('firebase-admin/auth');
const {
  getFirestore,
  FieldValue,
} = require('firebase-admin/firestore');
const {
  createClient,
} = require('@supabase/supabase-js');

const router = express.Router();

const supabaseUrl =
  (process.env.SUPABASE_URL || '').trim();

const supabaseSecretKey =
  (process.env.SUPABASE_SECRET_KEY || '').trim();

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

function setPrivateResponseHeaders(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
}

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

    if (!authorization.startsWith('Bearer ')) {
      return res.status(401).json({
        error:
          'Kimlik doğrulama bilgisi eksik.',
      });
    }

    const idToken =
      authorization.substring(7).trim();

    if (!idToken) {
      return res.status(401).json({
        error:
          'Firebase kimlik jetonu eksik.',
      });
    }

    // İptal edilmiş oturumları da kontrol eder.
    const decodedToken =
      await getAuth().verifyIdToken(
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
      error?.code || error?.message,
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

function decodeBase64Url(value) {
  try {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.length > 500 ||
      !/^[A-Za-z0-9_-]+={0,2}$/.test(value)
    ) {
      return null;
    }

    const decoded =
      Buffer.from(value, 'base64url');

    if (decoded.length === 0) {
      return null;
    }

    return decoded;
  } catch (_) {
    return null;
  }
}
function isValidPhotoId(value) {
  return (
    typeof value === 'string' &&
    /^[A-Za-z0-9_-]{22}$/.test(value)
  );
}

// ============================================================
// KASA ANAHTAR ZARFINI KAYDET
// PUT /api/vault/key-envelope
// ============================================================

router.put(
  '/key-envelope',
  verifyFirebaseUser,
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const uid = req.firebaseUser.uid;

      const {
        version,
        iterations,
        salt,
        wrappedKey,
      } = req.body || {};

      if (version !== 1) {
        return res.status(400).json({
          error: 'Geçersiz kasa sürümü.',
        });
      }

      if (
        !Number.isInteger(iterations) ||
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
        decodeBase64Url(wrappedKey);

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

      const firestore = getFirestore();

      const configRef =
        firestore
          .collection('private_vault_configs')
          .doc(uid);

      const documentData = {
        ownerId: uid,
        version,
        iterations,
        salt,
        wrappedKey,
        createdAt:
          FieldValue.serverTimestamp(),
        updatedAt:
          FieldValue.serverTimestamp(),
      };

      // Var olan anahtar zarfının yanlışlıkla üzerine
      // yazılmasını işlem (transaction) içinde engeller.
      const created =
        await firestore.runTransaction(
          async (transaction) => {
            const existing =
              await transaction.get(configRef);

            if (existing.exists) {
              return false;
            }

            transaction.set(
              configRef,
              documentData,
            );

            return true;
          },
        );

      if (!created) {
        return res.status(409).json({
          error:
            'Kasa anahtarı zaten mevcut. '
            + 'Üzerine yazılmadı.',
        });
      }

      return res.status(201).json({
        success: true,
      });
    } catch (error) {
      console.error(
        'Kasa anahtar kaydetme hatası:',
        error?.code || error?.message,
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
    setPrivateResponseHeaders(res);

    try {
      const uid = req.firebaseUser.uid;

      const document =
        await getFirestore()
          .collection('private_vault_configs')
          .doc(uid)
          .get();

      if (!document.exists) {
        return res.status(404).json({
          error:
            'Kasa anahtarı henüz oluşturulmamış.',
        });
      }

      const data = document.data() || {};

      return res.status(200).json({
        version: data.version,
        iterations: data.iterations,
        salt: data.salt,
        wrappedKey: data.wrappedKey,
      });
    } catch (error) {
      console.error(
        'Kasa anahtar okuma hatası:',
        error?.code || error?.message,
      );

      return res.status(500).json({
        error:
          'Kasa anahtar bilgisi alınamadı.',
      });
    }
  },
);

// ============================================================
// ============================================================
// ŞİFRELİ FOTOĞRAFLARI LİSTELE
// GET /api/vault/photos
// ============================================================

router.get(
  '/photos',
  verifyFirebaseUser,
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const uid =
        req.firebaseUser.uid;

      const {
        data,
        error,
      } = await supabaseAdmin
        .storage
        .from(vaultBucket)
        .list(
          uid,
          {
            limit: 100,
            offset: 0,
            sortBy: {
              column: 'created_at',
              order: 'desc',
            },
          },
        );

      if (error) {
        console.error(
          'Supabase vault listeleme hatası:',
          error.message,
        );

        return res.status(500).json({
          error:
            'Şifreli fotoğraflar listelenemedi.',
        });
      }

      const photos =
        (data || [])
          .map((file) => {
            const match =
              /^([A-Za-z0-9_-]{22})\.vault$/
                .exec(
                  file.name || '',
                );

            if (!match || !file.id) {
              return null;
            }

            const rawSize =
              Number(
                file.metadata?.size || 0,
              );

            return {
              photoId: match[1],
              encryptedSize:
                Number.isFinite(rawSize)
                  ? Math.max(
                      0,
                      Math.trunc(rawSize),
                    )
                  : 0,
              createdAt:
                file.created_at || null,
            };
          })
          .filter(Boolean);

      return res.status(200).json({
        photos,
      });
    } catch (error) {
      console.error(
        'Vault listeleme hatası:',
        error?.code || error?.message,
      );

      return res.status(500).json({
        error:
          'Şifreli fotoğraflar listelenemedi.',
      });
    }
  },
);
// ============================================================
// ŞİFRELİ FOTOĞRAFI İNDİR
// GET /api/vault/photos/:photoId
// ============================================================

router.get(
  '/photos/:photoId',
  verifyFirebaseUser,
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const uid =
        req.firebaseUser.uid;

      const photoId =
        (
          req.params.photoId ||
          ''
        ).trim();

      if (!isValidPhotoId(photoId)) {
        return res.status(400).json({
          error:
            'Geçersiz kasa fotoğraf kimliği.',
        });
      }

      const storagePath =
        `${uid}/${photoId}.vault`;

      const {
        data,
        error,
      } = await supabaseAdmin
        .storage
        .from(vaultBucket)
        .download(storagePath);

      if (error) {
        const statusCode =
          Number(
            error.statusCode ||
            error.status,
          );

        if (statusCode === 404) {
          return res.status(404).json({
            error:
              'Şifreli fotoğraf bulunamadı.',
          });
        }

        console.error(
          'Supabase vault indirme hatası:',
          error.message,
        );

        return res.status(500).json({
          error:
            'Şifreli fotoğraf indirilemedi.',
        });
      }

      const encryptedBytes =
        Buffer.from(
          await data.arrayBuffer(),
        );

      if (
        encryptedBytes.length < 33 ||
        encryptedBytes[0] !== 0x41 ||
        encryptedBytes[1] !== 0x4B ||
        encryptedBytes[2] !== 0x56 ||
        encryptedBytes[3] !== 0x31
      ) {
        return res.status(500).json({
          error:
            'Şifreli fotoğraf dosyası bozuk.',
        });
      }

      res.set(
        'Content-Type',
        'application/octet-stream',
      );

      res.set(
        'Content-Length',
        String(
          encryptedBytes.length,
        ),
      );

      res.set(
        'X-Content-Type-Options',
        'nosniff',
      );

      return res.status(200).send(
        encryptedBytes,
      );
    } catch (error) {
      console.error(
        'Vault indirme hatası:',
        error?.code || error?.message,
      );

      return res.status(500).json({
        error:
          'Şifreli fotoğraf indirilemedi.',
      });
    }
  },
);
// ŞİFRELİ FOTOĞRAF YÜKLE

// POST /api/vault/upload
// ============================================================


router.post(
  '/upload/:photoId',
  verifyFirebaseUser,
  express.raw({
    type: 'application/octet-stream',
    limit: '15mb',
  }),
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const encryptedBytes = req.body;

      if (
        !Buffer.isBuffer(encryptedBytes) ||
        encryptedBytes.length < 33
      ) {
        return res.status(400).json({
          error:
            'Şifreli dosya verisi bulunamadı.',
        });
      }

      // Şifreli kasa dosyası AKV1 başlığıyla başlamalıdır.
      if (
        encryptedBytes[0] !== 0x41 ||
        encryptedBytes[1] !== 0x4B ||
        encryptedBytes[2] !== 0x56 ||
        encryptedBytes[3] !== 0x31
      ) {
        return res.status(400).json({
          error:
            'Dosya şifreli kasa biçiminde değil.',
        });
      }

const uid =
  req.firebaseUser.uid;

const photoId =
  (req.params.photoId || '').trim();

if (!isValidPhotoId(photoId)) {
  return res.status(400).json({
    error:
      'Geçersiz kasa fotoğraf kimliği.',
  });
}

// Kullanıcı, dosya yolunu kendisi belirleyemez.
// Yol doğrulanan Firebase UID'sinden oluşur.
const storagePath =
  `${uid}/${photoId}.vault`;

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
  fileId: photoId,
  storagePath:
    data.path,
        encryptedSize:
          encryptedBytes.length,
      });
    } catch (error) {
      console.error(
        'Vault yükleme hatası:',
        error?.code || error?.message,
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
    if (error?.type === 'entity.too.large') {
      return res.status(413).json({
        error:
          'Şifreli dosyanın boyutu '
          + '15 MB sınırını aşıyor.',
      });
    }

    return next(error);
  },
);

module.exports = router;
