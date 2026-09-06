"use strict";

/*
╔══════════════════════════════════════════════╗
║             NEVLIZ ACCOUNT API               ║
║                  v1.0.0                      ║
╚══════════════════════════════════════════════╝

Endpoints:

POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me

Environment variables:

DATABASE_URL
JWT_SECRET
PORT
*/

// ======================================================
// DEPENDÊNCIAS
// ======================================================

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

// ======================================================
// CONFIGURAÇÃO
// ======================================================

const app = express();

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

// ======================================================
// VERIFICAÇÃO DE CONFIGURAÇÃO
// ======================================================

if (!DATABASE_URL) {
    console.error("ERRO: DATABASE_URL não foi configurada.");
    process.exit(1);
}

if (!JWT_SECRET) {
    console.error("ERRO: JWT_SECRET não foi configurada.");
    process.exit(1);
}

// ======================================================
// MIDDLEWARE
// ======================================================

app.use(express.json({
    limit: "10kb"
}));

// ======================================================
// POSTGRESQL
// ======================================================

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.on("error", (error) => {
    console.error("Erro inesperado no PostgreSQL:", error);
});

// ======================================================
// BANCO DE DADOS
// ======================================================

async function initializeDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(32) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    console.log("Banco de dados inicializado.");
}

// ======================================================
// FUNÇÕES AUXILIARES
// ======================================================

function normalizeUsername(username) {
    return String(username || "")
        .trim()
        .toLowerCase();
}

function validateUsername(username) {
    if (!username) {
        return "Digite seu nick.";
    }

    if (username.length < 3) {
        return "O nick precisa ter pelo menos 3 caracteres.";
    }

    if (username.length > 32) {
        return "O nick pode ter no máximo 32 caracteres.";
    }

    /*
     * Permitimos letras, números, underscore e hífen.
     */
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        return "O nick contém caracteres inválidos.";
    }

    return null;
}

function validatePassword(password) {
    if (!password) {
        return "Digite uma senha.";
    }

    if (password.length < 6) {
        return "A senha precisa ter pelo menos 6 caracteres.";
    }

    if (password.length > 128) {
        return "A senha pode ter no máximo 128 caracteres.";
    }

    return null;
}

function createToken(user) {
    return jwt.sign(
        {
            userId: String(user.id),
            username: user.username
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

// ======================================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ======================================================

function authenticate(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization) {
        return res.status(401).json({
            success: false,
            message: "Sessão não fornecida."
        });
    }

    const parts = authorization.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return res.status(401).json({
            success: false,
            message: "Token inválido."
        });
    }

    const token = parts[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Sessão expirada ou inválida."
        });
    }
}

// ======================================================
// HEALTH CHECK
// ======================================================

app.get("/", (req, res) => {
    res.json({
        success: true,
        service: "Nevliz Account API",
        version: "1.0.0",
        status: "online"
    });
});

// ======================================================
// REGISTER
// ======================================================

app.post("/api/auth/register", async (req, res) => {
    try {
        const { username, password } = req.body || {};

        const cleanUsername = normalizeUsername(username);

        const usernameError = validateUsername(cleanUsername);

        if (usernameError) {
            return res.status(400).json({
                success: false,
                message: usernameError
            });
        }

        const passwordError = validatePassword(password);

        if (passwordError) {
            return res.status(400).json({
                success: false,
                message: passwordError
            });
        }

        // Verificar se já existe
        const existingUser = await pool.query(
            `
            SELECT id
            FROM users
            WHERE username = $1
            LIMIT 1
            `,
            [cleanUsername]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Esse usuário já possui uma conta."
            });
        }

        // Criar hash da senha
        const passwordHash = await bcrypt.hash(password, 12);

        // Criar usuário
        const result = await pool.query(
            `
            INSERT INTO users
                (username, password_hash)
            VALUES
                ($1, $2)
            RETURNING id, username, created_at
            `,
            [
                cleanUsername,
                passwordHash
            ]
        );

        const user = result.rows[0];

        // Criar sessão
        const token = createToken(user);

        return res.status(201).json({
            success: true,
            message: "Conta criada com sucesso.",
            token: token,
            user: {
                id: String(user.id),
                username: user.username,
                createdAt: user.created_at
            }
        });

    } catch (error) {
        console.error("REGISTER ERROR:", error);

        /*
         * PostgreSQL unique violation.
         */
        if (error.code === "23505") {
            return res.status(409).json({
                success: false,
                message: "Esse usuário já possui uma conta."
            });
        }

        return res.status(500).json({
            success: false,
            message: "Erro interno ao criar a conta."
        });
    }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body || {};

        const cleanUsername = normalizeUsername(username);

        const usernameError = validateUsername(cleanUsername);

        if (usernameError) {
            return res.status(400).json({
                success: false,
                message: usernameError
            });
        }

        if (!password) {
            return res.status(400).json({
                success: false,
                message: "Digite sua senha."
            });
        }

        // Buscar usuário
        const result = await pool.query(
            `
            SELECT
                id,
                username,
                password_hash,
                created_at
            FROM users
            WHERE username = $1
            LIMIT 1
            `,
            [cleanUsername]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Usuário ou senha incorretos."
            });
        }

        const user = result.rows[0];

        // Comparar senha
        const passwordCorrect = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordCorrect) {
            return res.status(401).json({
                success: false,
                message: "Usuário ou senha incorretos."
            });
        }

        // Criar token
        const token = createToken(user);

        return res.status(200).json({
            success: true,
            message: "Login realizado com sucesso.",
            token: token,
            user: {
                id: String(user.id),
                username: user.username,
                createdAt: user.created_at
            }
        });

    } catch (error) {
        console.error("LOGIN ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Erro interno ao realizar login."
        });
    }
});

// ======================================================
// ME
// ======================================================

app.get("/api/auth/me", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `
            SELECT
                id,
                username,
                created_at
            FROM users
            WHERE id = $1
            LIMIT 1
            `,
            [req.user.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Conta não encontrada."
            });
        }

        const user = result.rows[0];

        return res.status(200).json({
            success: true,
            user: {
                id: String(user.id),
                username: user.username,
                createdAt: user.created_at
            }
        });

    } catch (error) {
        console.error("ME ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Erro interno ao verificar a sessão."
        });
    }
});

// ======================================================
// LOGOUT
// ======================================================

app.post("/api/auth/logout", authenticate, async (req, res) => {
    /*
     * Como estamos usando JWT stateless, o servidor não precisa
     * armazenar a sessão.
     *
     * O Delta deve apagar o DataaccountNevliz.json.
     */

    return res.status(200).json({
        success: true,
        message: "Logout realizado com sucesso."
    });
});

// ======================================================
// 404
// ======================================================

app.use((req, res) => {
    return res.status(404).json({
        success: false,
        message: "Endpoint não encontrado."
    });
});

// ======================================================
// ERROS JSON
// ======================================================

app.use((error, req, res, next) => {
    console.error("SERVER ERROR:", error);

    return res.status(500).json({
        success: false,
        message: "Erro interno do servidor."
    });
});

// ======================================================
// INICIAR
// ======================================================

async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, "0.0.0.0", () => {
            console.log("======================================");
            console.log("      NEVLIZ ACCOUNT API ONLINE");
            console.log("======================================");
            console.log(`Porta: ${PORT}`);
            console.log("Banco: conectado");
        });

    } catch (error) {
        console.error("Não foi possível iniciar o servidor:");
        console.error(error);

        process.exit(1);
    }
}

startServer();
