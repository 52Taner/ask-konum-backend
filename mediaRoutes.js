const express = require('express');
const crypto = require('crypto');

const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const {
  createClient,
} = require('@supabase/supabase-js');

const router = express.Router();

const supabaseUrl =
  (process.env.SUPABASE_URL || '').trim();

const supabaseSecretKey =
  (process.env.SUPABASE_SECRET_KEY || '').trim();

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

const allowedBuckets = new Set([
  'memories',
  'chat-files',
  'voice-notes',
]);

const signedUrlLifetimeSeconds = 5 * 60;
const maximumUploadSize = 15 * 1024 * 1024;
const maximumImageSize = 10 * 1024 * 1024;

function setPrivateResponseHeaders(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  res.set('X-Content-Type-Options', 'nosniff');
}

function isValidUid(value) {
  return (
    typeof value === 'string' &&
    /^[A-Za-z0-9_-]{1,128}$/.test(value)
  );
}

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

    const decodedToken =
      await getAuth().verifyIdToken(
        idToken,
        true,
      );

    const uid =
      (decodedToken.uid || '').trim();

    if (!isValidUid(uid)) {
      return res.status(403).json({
        error:
          'Geçersiz kullanıcı kimliği.',
      });
    }

    req.firebaseUser = decodedToken;
    return next();
  } catch (error) {
    console.error(
      'Medya kimlik doğrulama hatası:',
      error?.code || error?.message,
    );

    return res.status(401).json({
      error:
        'Oturum geçersiz veya süresi dolmuş.',
    });
  }
}

async function getPairContext(uid) {
  const firestore = getFirestore();

  const myDocument =
    await firestore
      .collection('locations')
      .doc(uid)
      .get();

  if (!myDocument.exists) {
    return null;
  }

  const partnerId =
    (
      myDocument.data()?.partnerId ||
      ''
    ).trim();

  if (
    !isValidUid(partnerId) ||
    partnerId === uid
  ) {
    return null;
  }

  const partnerDocument =
    await firestore
      .collection('locations')
      .doc(partnerId)
      .get();

  if (!partnerDocument.exists) {
    return null;
  }

  const partnerBackLink =
    (
      partnerDocument.data()?.partnerId ||
      ''
    ).trim();

  if (partnerBackLink !== uid) {
    return null;
  }

  const ids = [uid, partnerId].sort();

  return {
    uid,
    partnerId,
    pairId: `${ids[0]}_${ids[1]}`,
  };
}

function isSafeStoragePath(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 400 &&
    !value.startsWith('/') &&
    !value.endsWith('/') &&
    !value.includes('..') &&
    !value.includes('\\') &&
    !value.includes('//') &&
    /^[A-Za-z0-9._/-]+$/.test(value)
  );
}

function escapeRegularExpression(value) {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    '\\$&',
  );
}

function isAllowedPairPath(
  bucket,
  storagePath,
  pairId,
) {
  if (
    !allowedBuckets.has(bucket) ||
    !isSafeStoragePath(storagePath)
  ) {
    return false;
  }

  const escapedPairId =
    escapeRegularExpression(pairId);

  const imageName =
    '[A-Za-z0-9_-]{1,160}'
    + '[.](?:jpg|jpeg|png|webp|gif)';

  const audioName =
    '[A-Za-z0-9_-]{1,160}[.]webm';

  if (bucket === 'memories') {
    return new RegExp(
      `^${escapedPairId}/${imageName}$`,
    ).test(storagePath);
  }

  if (bucket === 'voice-notes') {
    return new RegExp(
      `^${escapedPairId}/${audioName}$`,
    ).test(storagePath);
  }

  if (bucket === 'chat-files') {
    const imagePattern = new RegExp(
      `^images/${escapedPairId}/${imageName}$`,
    );

    const audioPattern = new RegExp(
      `^audio/${escapedPairId}/${audioName}$`,
    );

    return (
      imagePattern.test(storagePath) ||
      audioPattern.test(storagePath)
    );
  }

  return false;
}

function detectImage(bytes) {
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xFF &&
    bytes[1] === 0xD8 &&
    bytes[2] === 0xFF
  ) {
    return {
      extension: 'jpg',
      contentType: 'image/jpeg',
    };
  }

  if (
    bytes.length >= 8 &&
    bytes.subarray(0, 8).equals(
      Buffer.from([
        0x89,
        0x50,
        0x4E,
        0x47,
        0x0D,
        0x0A,
        0x1A,
        0x0A,
      ]),
    )
  ) {
    return {
      extension: 'png',
      contentType: 'image/png',
    };
  }

  if (
    bytes.length >= 12 &&
    bytes.toString('ascii', 0, 4) === 'RIFF' &&
    bytes.toString('ascii', 8, 12) === 'WEBP'
  ) {
    return {
      extension: 'webp',
      contentType: 'image/webp',
    };
  }

  const gifHeader =
    bytes.length >= 6
      ? bytes.toString('ascii', 0, 6)
      : '';

  if (
    gifHeader === 'GIF87a' ||
    gifHeader === 'GIF89a'
  ) {
    return {
      extension: 'gif',
      contentType: 'image/gif',
    };
  }

  return null;
}

function isWebm(bytes) {
  return (
    bytes.length >= 4 &&
    bytes[0] === 0x1A &&
    bytes[1] === 0x45 &&
    bytes[2] === 0xDF &&
    bytes[3] === 0xA3
  );
}

function buildUploadTarget(
  kind,
  bytes,
  pairId,
) {
  const fileId = crypto.randomUUID();

  if (
    kind === 'memory-image' ||
    kind === 'chat-image'
  ) {
    if (bytes.length > maximumImageSize) {
      return {
        error:
          'Fotoğraf 10 MB sınırını aşıyor.',
        statusCode: 413,
      };
    }

    const image = detectImage(bytes);

    if (image == null) {
      return {
        error:
          'Desteklenmeyen veya bozuk fotoğraf.',
        statusCode: 400,
      };
    }

    const fileName =
      `${fileId}.${image.extension}`;

    return {
      fileId,
      bucket:
        kind === 'memory-image'
          ? 'memories'
          : 'chat-files',
      storagePath:
        kind === 'memory-image'
          ? `${pairId}/${fileName}`
          : `images/${pairId}/${fileName}`,
      contentType: image.contentType,
    };
  }

  if (
    kind === 'chat-audio' ||
    kind === 'calendar-audio'
  ) {
    if (!isWebm(bytes)) {
      return {
        error:
          'Desteklenmeyen veya bozuk ses kaydı.',
        statusCode: 400,
      };
    }

    const fileName = `${fileId}.webm`;

    return {
      fileId,
      bucket:
        kind === 'chat-audio'
          ? 'chat-files'
          : 'voice-notes',
      storagePath:
        kind === 'chat-audio'
          ? `audio/${pairId}/${fileName}`
          : `${pairId}/${fileName}`,
      contentType: 'audio/webm',
    };
  }

  return {
    error: 'Geçersiz medya türü.',
    statusCode: 400,
  };
}

async function createSignedUrl(
  bucket,
  storagePath,
) {
  const {
    data,
    error,
  } = await supabaseAdmin
    .storage
    .from(bucket)
    .createSignedUrl(
      storagePath,
      signedUrlLifetimeSeconds,
    );

  if (error || !data?.signedUrl) {
    throw new Error(
      error?.message ||
      'İmzalı medya bağlantısı oluşturulamadı.',
    );
  }

  return data.signedUrl;
}

// ============================================================
// MEDYA YÜKLE
// POST /api/media/upload/:kind
// ============================================================

router.post(
  '/upload/:kind',
  verifyFirebaseUser,
  express.raw({
    type: 'application/octet-stream',
    limit: '15mb',
  }),
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const bytes = req.body;

      if (
        !Buffer.isBuffer(bytes) ||
        bytes.length === 0
      ) {
        return res.status(400).json({
          error:
            'Medya dosyası bulunamadı.',
        });
      }

      if (bytes.length > maximumUploadSize) {
        return res.status(413).json({
          error:
            'Dosya 15 MB sınırını aşıyor.',
        });
      }

      const uid = req.firebaseUser.uid;
      const pair = await getPairContext(uid);

      if (pair == null) {
        return res.status(403).json({
          error:
            'Karşılıklı partner eşleşmesi doğrulanamadı.',
        });
      }

      const kind =
        (req.params.kind || '').trim();

      const target = buildUploadTarget(
        kind,
        bytes,
        pair.pairId,
      );

      if (target.error) {
        return res
          .status(target.statusCode || 400)
          .json({
            error: target.error,
          });
      }

      const {
        data,
        error,
      } = await supabaseAdmin
        .storage
        .from(target.bucket)
        .upload(
          target.storagePath,
          bytes,
          {
            contentType: target.contentType,
            cacheControl: '0',
            upsert: false,
          },
        );

      if (error) {
        console.error(
          'Güvenli medya yükleme hatası:',
          error.message,
        );

        return res.status(500).json({
          error:
            'Medya dosyası kaydedilemedi.',
        });
      }

      const signedUrl =
        await createSignedUrl(
          target.bucket,
          data.path,
        );

      return res.status(201).json({
        success: true,
        fileId: target.fileId,
        bucket: target.bucket,
        storagePath: data.path,
        contentType: target.contentType,
        size: bytes.length,
        signedUrl,
        expiresIn: signedUrlLifetimeSeconds,
      });
    } catch (error) {
      console.error(
        'Güvenli medya yükleme hatası:',
        error?.code || error?.message,
      );

      return res.status(500).json({
        error:
          'Medya yükleme işlemi başarısız.',
      });
    }
  },
);

// ============================================================
// KISA SÜRELİ GÖRÜNTÜLEME BAĞLANTISI
// POST /api/media/sign
// ============================================================

router.post(
  '/sign',
  verifyFirebaseUser,
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const uid = req.firebaseUser.uid;
      const pair = await getPairContext(uid);

      if (pair == null) {
        return res.status(403).json({
          error:
            'Karşılıklı partner eşleşmesi doğrulanamadı.',
        });
      }

      const bucket =
        (req.body?.bucket || '').trim();

      const storagePath =
        (req.body?.storagePath || '').trim();

      if (
        !isAllowedPairPath(
          bucket,
          storagePath,
          pair.pairId,
        )
      ) {
        return res.status(403).json({
          error:
            'Bu medya dosyasına erişim yetkiniz yok.',
        });
      }

      const signedUrl =
        await createSignedUrl(
          bucket,
          storagePath,
        );

      return res.status(200).json({
        signedUrl,
        expiresIn: signedUrlLifetimeSeconds,
      });
    } catch (error) {
      console.error(
        'Medya bağlantısı oluşturma hatası:',
        error?.code || error?.message,
      );

      return res.status(500).json({
        error:
          'Güvenli medya bağlantısı oluşturulamadı.',
      });
    }
  },
);

// ============================================================
// MEDYA DOSYASINI SİL
// DELETE /api/media/file
// ============================================================

router.delete(
  '/file',
  verifyFirebaseUser,
  async (req, res) => {
    setPrivateResponseHeaders(res);

    try {
      const uid = req.firebaseUser.uid;
      const pair = await getPairContext(uid);

      if (pair == null) {
        return res.status(403).json({
          error:
            'Karşılıklı partner eşleşmesi doğrulanamadı.',
        });
      }

      const bucket =
        (req.body?.bucket || '').trim();

      const storagePath =
        (req.body?.storagePath || '').trim();

      if (
        !isAllowedPairPath(
          bucket,
          storagePath,
          pair.pairId,
        )
      ) {
        return res.status(403).json({
          error:
            'Bu medya dosyasını silme yetkiniz yok.',
        });
      }

      const { error } =
        await supabaseAdmin
          .storage
          .from(bucket)
          .remove([storagePath]);

      if (error) {
        console.error(
          'Güvenli medya silme hatası:',
          error.message,
        );

        return res.status(500).json({
          error:
            'Medya dosyası silinemedi.',
        });
      }

      return res.status(200).json({
        success: true,
      });
    } catch (error) {
      console.error(
        'Güvenli medya silme hatası:',
        error?.code || error?.message,
      );

      return res.status(500).json({
        error:
          'Medya silme işlemi başarısız.',
      });
    }
  },
);

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
          'Dosya 15 MB sınırını aşıyor.',
      });
    }

    return next(error);
  },
);

module.exports = router;
