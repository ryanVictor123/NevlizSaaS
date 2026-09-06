const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");
const { rateLimit } = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

const JWT_EXPIRES_IN = "7d";
const BCRYPT_ROUNDS = 12;

if (!DATABASE_URL) {
  console.error("ERRO: DATABASE_URL não configurada.");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("ERRO: JWT_SECRET não configurada.");
  process.exit(1);
}

/*
==================================================
CONFIGURAÇÃO DO EXPRESS
==================================================
*/

app.set("trust proxy", 1);

app.use(
  express.json({
    limit: "10kb"
  })
);

/*
==================================================
DATABASE
==================================================
*/

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl: {
    rejectUnauthorized: false
  },

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

/*
==================================================
RATE LIMIT
==================================================
*/

/*
  Limite geral da API.

  Não impede 100 usuários legítimos de usar o sistema.
  Ele serve principalmente para impedir spam extremo.
*/

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,

  message: {
    success: false,
    message: "Muitas requisições. Tente novamente mais tarde."
  }
});

/*
  Cadastro.

  20 tentativas por IP a cada 15 minutos.
*/

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,

  message: {
    success: false,
    message: "Muitas tentativas de cadastro. Tente novamente mais tarde."
  }
});

/*
  Login.

  Mais restritivo para dificultar força bruta.
*/

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,

  message: {
    success: false,
    message: "Muitas tentativas de login. Aguarde alguns minutos."
  }
});

/*
  Troca de senha.

  Também protegida contra spam.
*/

const passwordLimiter = rateLimit({
  windowMs: 15 * 15 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,

  message: {
    success: false,
    message: "Muitas tentativas de alteração de senha."
  }
});

app.use("/api", generalLimiter);

/*
==================================================
CONTROLE DE CONCORRÊNCIA DO BCRYPT
==================================================
*/

/*
  O bcrypt é propositalmente pesado.

  Em vez de permitir centenas de hashes simultaneamente,
  limitamos a quantidade de hashes sendo processados.

  Isso ajuda a proteger o servidor durante picos.
*/

const HASH_CONCURRENCY = 4;
const HASH_QUEUE_LIMIT = 100;

let activeHashes = 0;
const hashQueue = [];

function processHashQueue() {
  while (
    activeHashes < HASH_CONCURRENCY &&
    hashQueue.length > 0
  ) {
    const job = hashQueue.shift();

    activeHashes++;

    bcrypt
      .hash(job.password, BCRYPT_ROUNDS)
      .then((hash) => {
        activeHashes--;
        job.resolve(hash);
        processHashQueue();
      })
      .catch((error) => {
        activeHashes--;
        job.reject(error);
        processHashQueue();
      });
  }
}

function safeHash(password) {
  return new Promise((resolve, reject) => {
    if (hashQueue.length >= HASH_QUEUE_LIMIT) {
      return reject(
        new Error("Servidor ocupado. Tente novamente.")
      );
    }

    hashQueue.push({
      password,
      resolve,
      reject
    });

    processHashQueue();
  });
}

/*
==================================================
VALIDAÇÃO
==================================================
*/

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase();
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_-]{3,32}$/.test(username);
}

function isValidPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 72
  );
}

/*
==================================================
JWT / SESSÕES
==================================================
*/

function createToken(userId, username, jti) {
  return jwt.sign(
    {
      sub: String(userId),
      username,
      jti
    },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRES_IN
    }
  );
}

async function createSession(userId, username) {
  const jti = crypto.randomUUID();

  const token = createToken(
    userId,
    username,
    jti
  );

  const decoded = jwt.decode(token);

  const expiresAt = new Date(decoded.exp * 1000);

  await pool.query(
    `
    INSERT INTO sessions
      (jti, user_id, expires_at)
    VALUES
      ($1, $2, $3)
    `,
    [
      jti,
      userId,
      expiresAt
    ]
  );

  return token;
}

/*
==================================================
AUTH MIDDLEWARE
==================================================
*/

async function authenticate(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Sessão não encontrada."
      });
    }

    const token =
      authorization.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token inválido."
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    if (!decoded.jti || !decoded.sub) {
      return res.status(401).json({
        success: false,
        message: "Sessão inválida."
      });
    }

    const result = await pool.query(
      `
      SELECT
        s.id,
        s.jti,
        s.user_id,
        s.expires_at,
        s.revoked_at,
        u.username
      FROM sessions s
      INNER JOIN users u
        ON u.id = s.user_id
      WHERE s.jti = $1
        AND s.user_id = $2
      LIMIT 1
      `,
      [
        decoded.jti,
        decoded.sub
      ]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Sessão não encontrada."
      });
    }

    const session = result.rows[0];

    if (session.revoked_at) {
      return res.status(401).json({
        success: false,
        message: "Esta sessão foi encerrada."
      });
    }

    if (
      new Date(session.expires_at).getTime() <=
      Date.now()
    ) {
      return res.status(401).json({
        success: false,
        message: "Sua sessão expirou."
      });
    }

    req.user = {
      id: Number(session.user_id),
      username: session.username
    };

    req.session = session;
    req.tokenJti = decoded.jti;

    next();
  } catch (error) {
    if (
      error.name === "TokenExpiredError"
    ) {
      return res.status(401).json({
        success: false,
        message: "Sua sessão expirou."
      });
    }

    if (
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({
        success: false,
        message: "Token inválido."
      });
    }

    console.error(
      "Erro na autenticação:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Erro interno do servidor."
    });
  }
}

/*
==================================================
DATABASE INIT
==================================================
*/

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,

      username VARCHAR(32)
        UNIQUE
        NOT NULL,

      password_hash TEXT
        NOT NULL,

      created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,

      jti UUID
        UNIQUE
        NOT NULL,

      user_id BIGINT
        NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      expires_at TIMESTAMPTZ
        NOT NULL,

      created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      revoked_at TIMESTAMPTZ
        NULL
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_jti
    ON sessions(jti);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);
  `);

  console.log("Banco de dados inicializado.");
}

/*
==================================================
HEALTH CHECK
==================================================
*/

app.get("/", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      service: "Nevliz Account API",
      version: "2.0.0",
      status: "online",
      database: "connected"
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      service: "Nevliz Account API",
      status: "degraded",
      database: "disconnected"
    });
  }
});

/*
==================================================
REGISTER
==================================================
*/

app.post(
  "/api/auth/register",
  registerLimiter,
  async (req, res) => {
    try {
      const username =
        normalizeUsername(req.body.username);

      const password =
        req.body.password;

      if (!isValidUsername(username)) {
        return res.status(400).json({
          success: false,
          message:
            "Usuário deve ter entre 3 e 32 caracteres e usar apenas letras, números, _ ou -."
        });
      }

      if (!isValidPassword(password)) {
        return res.status(400).json({
          success: false,
          message:
            "A senha deve ter entre 8 e 72 caracteres."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE username = $1
          LIMIT 1
          `,
          [username]
        );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: "Esse usuário já existe."
        });
      }

      let passwordHash;

      try {
        passwordHash =
          await safeHash(password);
      } catch (hashError) {
        if (
          hashError.message ===
          "Servidor ocupado. Tente novamente."
        ) {
          return res.status(503).json({
            success: false,
            message:
              "O servidor está ocupado. Tente novamente em alguns segundos."
          });
        }

        throw hashError;
      }

      const result =
        await pool.query(
          `
          INSERT INTO users
            (username, password_hash)
          VALUES
            ($1, $2)
          RETURNING
            id,
            username,
            created_at
          `,
          [
            username,
            passwordHash
          ]
        );

      const user =
        result.rows[0];

      const token =
        await createSession(
          user.id,
          user.username
        );

      return res.status(201).json({
        success: true,
        message: "Conta criada com sucesso.",
        token,
        user: {
          id: Number(user.id),
          username: user.username
        }
      });
    } catch (error) {
      console.error(
        "Erro no registro:",
        error
      );

      if (
        error.code === "23505"
      ) {
        return res.status(409).json({
          success: false,
          message: "Esse usuário já existe."
        });
      }

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao criar a conta."
      });
    }
  }
);

/*
==================================================
LOGIN
==================================================
*/

app.post(
  "/api/auth/login",
  loginLimiter,
  async (req, res) => {
    try {
      const username =
        normalizeUsername(req.body.username);

      const password =
        req.body.password;

      if (!username || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Usuário e senha são obrigatórios."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            password_hash
          FROM users
          WHERE username = $1
          LIMIT 1
          `,
          [username]
        );

      if (result.rows.length === 0) {
        return res.status(401).json({
          success: false,
          message:
            "Usuário ou senha incorretos."
        });
      }

      const user =
        result.rows[0];

      const passwordCorrect =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordCorrect) {
        return res.status(401).json({
          success: false,
          message:
            "Usuário ou senha incorretos."
        });
      }

      const token =
        await createSession(
          user.id,
          user.username
        );

      return res.json({
        success: true,
        message: "Login realizado com sucesso.",
        token,
        user: {
          id: Number(user.id),
          username: user.username
        }
      });
    } catch (error) {
      console.error(
        "Erro no login:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao realizar login."
      });
    }
  }
);

/*
==================================================
ME
==================================================
*/

app.get(
  "/api/auth/me",
  authenticate,
  async (req, res) => {
    return res.json({
      success: true,
      user: {
        id: req.user.id,
        username: req.user.username
      }
    });
  }
);

/*
==================================================
ALTERAR SENHA
==================================================
*/

app.post(
  "/api/auth/change-password",
  passwordLimiter,
  authenticate,
  async (req, res) => {
    try {
      const currentPassword =
        req.body.currentPassword;

      const newPassword =
        req.body.newPassword;

      const confirmPassword =
        req.body.confirmPassword;

      if (
        typeof currentPassword !== "string" ||
        typeof newPassword !== "string" ||
        typeof confirmPassword !== "string"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Preencha todos os campos."
        });
      }

      if (
        !isValidPassword(newPassword)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "A nova senha deve ter entre 8 e 72 caracteres."
        });
      }

      if (
        newPassword !== confirmPassword
      ) {
        return res.status(400).json({
          success: false,
          message:
            "A confirmação da senha não corresponde."
        });
      }

      if (
        currentPassword === newPassword
      ) {
        return res.status(400).json({
          success: false,
          message:
            "A nova senha deve ser diferente da senha atual."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            username,
            password_hash
          FROM users
          WHERE id = $1
          LIMIT 1
          `,
          [req.user.id]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Usuário não encontrado."
        });
      }

      const user =
        result.rows[0];

      const currentPasswordCorrect =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!currentPasswordCorrect) {
        return res.status(401).json({
          success: false,
          message:
            "A senha atual está incorreta."
        });
      }

      let newPasswordHash;

      try {
        newPasswordHash =
          await safeHash(newPassword);
      } catch (hashError) {
        if (
          hashError.message ===
          "Servidor ocupado. Tente novamente."
        ) {
          return res.status(503).json({
            success: false,
            message:
              "O servidor está ocupado. Tente novamente em alguns segundos."
          });
        }

        throw hashError;
      }

      /*
        Atualiza a senha.
      */

      await pool.query(
        `
        UPDATE users
        SET
          password_hash = $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [
          newPasswordHash,
          req.user.id
        ]
      );

      /*
        Revoga TODAS as sessões existentes.

        Isso derruba qualquer dispositivo que
        estivesse conectado à conta.
      */

      await pool.query(
        `
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE user_id = $1
          AND revoked_at IS NULL
        `,
        [req.user.id]
      );

      /*
        Cria uma nova sessão para o dispositivo
        que acabou de trocar a senha.
      */

      const newToken =
        await createSession(
          user.id,
          user.username
        );

      return res.json({
        success: true,
        message:
          "Senha alterada com sucesso. As sessões antigas foram encerradas.",
        token: newToken,
        user: {
          id: Number(user.id),
          username: user.username
        }
      });
    } catch (error) {
      console.error(
        "Erro ao alterar senha:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao alterar a senha."
      });
    }
  }
);

/*
==================================================
LOGOUT
==================================================
*/

app.post(
  "/api/auth/logout",
  authenticate,
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE jti = $1
        `,
        [req.tokenJti]
      );

      return res.json({
        success: true,
        message:
          "Logout realizado com sucesso."
      });
    } catch (error) {
      console.error(
        "Erro no logout:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao realizar logout."
      });
    }
  }
);

/*
==================================================
LOGOUT DE TODOS OS DISPOSITIVOS
==================================================
*/

app.post(
  "/api/auth/logout-all",
  passwordLimiter,
  authenticate,
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE sessions
        SET revoked_at = NOW()
        WHERE user_id = $1
          AND revoked_at IS NULL
        `,
        [req.user.id]
      );

      return res.json({
        success: true,
        message:
          "Todas as sessões foram encerradas."
      });
    } catch (error) {
      console.error(
        "Erro no logout-all:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Erro interno ao encerrar as sessões."
      });
    }
  }
);

/*
==================================================
404
==================================================
*/

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "Endpoint não encontrado."
    });
  }
);

/*
==================================================
ERROR HANDLER
==================================================
*/

app.use(
  (error, req, res, next) => {
    console.error(
      "Erro não tratado:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Erro interno do servidor."
    });
  }
);

/*
==================================================
LIMPEZA AUTOMÁTICA DAS SESSÕES
==================================================
*/

async function cleanupSessions() {
  try {
    const result =
      await pool.query(
        `
        DELETE FROM sessions
        WHERE
          expires_at < NOW()
          OR (
            revoked_at IS NOT NULL
            AND revoked_at < NOW() - INTERVAL '7 days'
          )
        `
      );

    if (result.rowCount > 0) {
      console.log(
        `Sessões antigas removidas: ${result.rowCount}`
      );
    }
  } catch (error) {
    console.error(
      "Erro ao limpar sessões:",
      error
    );
  }
}

/*
  Executa limpeza a cada 30 minutos.
*/

setInterval(
  cleanupSessions,
  30 * 60 * 1000
);

/*
==================================================
START SERVER
==================================================
*/

async function startServer() {
  try {
    await initializeDatabase();

    await cleanupSessions();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log("");
        console.log(
          "======================================"
        );
        console.log(
          "       NEVLIZ ACCOUNT API ONLINE"
        );
        console.log(
          "======================================"
        );
        console.log(
          `Porta: ${PORT}`
        );
        console.log(
          "Banco: conectado"
        );
        console.log(
          "Sessões: habilitadas"
        );
        console.log(
          "Rate Limit: habilitado"
        );
        console.log(
          "Troca de senha: habilitada"
        );
        console.log(
          "======================================"
        );
        console.log("");
      }
    );
  } catch (error) {
    console.error(
      "Falha ao iniciar servidor:"
    );

    console.error(error);

    process.exit(1);
  }
}

startServer();
