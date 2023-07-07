"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserController = void 0;
const express_validator_1 = require("express-validator");
const DbClient_1 = require("./DbClient");
const bcrypt_1 = __importDefault(require("bcrypt"));
const crypto_1 = require("crypto");
const mail_config_1 = require("./mail_config");
class UserController {
    constructor(app) {
        this.dbClient = new DbClient_1.DbClient();
        this.configureRoutes(app);
        setInterval(() => __awaiter(this, void 0, void 0, function* () {
            const client = yield this.dbClient.connect();
            try {
                yield this.dbClient.queryWithParams(client, 'DELETE FROM clientes WHERE email_verified = FALSE AND created_at < NOW() - INTERVAL \'1 hour\'', []);
            }
            finally {
                client.release();
            }
        }), 1000 * 60 * 60); // executa a cada hora
    }
    configureRoutes(app) {
        app.post('/cadastro', [
            (0, express_validator_1.check)('name').notEmpty().withMessage('Full name is required'),
            (0, express_validator_1.check)('username').isEmail().withMessage('Invalid e-mail format'),
            (0, express_validator_1.check)('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long'),
            (0, express_validator_1.check)('data_nasc').notEmpty().withMessage('Date of birth is required')
        ], this.register.bind(this));
        app.post('/login', [
            (0, express_validator_1.check)('username').isEmail().withMessage('Invalid e-mail format'),
            (0, express_validator_1.check)('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long')
        ], this.login.bind(this));
        app.post('/update-name', [
            (0, express_validator_1.check)('username').isEmail().withMessage('Invalid e-mail format'),
            (0, express_validator_1.check)('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long'),
            (0, express_validator_1.check)('newName').notEmpty().withMessage('New name is required')
        ], this.updateName.bind(this));
        app.post('/update-dob', [
            (0, express_validator_1.check)('username').isEmail().withMessage('Invalid e-mail format'),
            (0, express_validator_1.check)('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long'),
            (0, express_validator_1.check)('newDOB').notEmpty().withMessage('New date of birth is required')
        ], this.updateDOB.bind(this));
        app.post('/delete-account', [
            (0, express_validator_1.check)('username').isEmail().withMessage('Invalid e-mail format'),
            (0, express_validator_1.check)('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long')
        ], this.deleteAccount.bind(this));
        app.route('/usuarios/verificar-email/:token')
            .get(this.verifyEmail.bind(this));
    }
    register(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const client = yield this.dbClient.connect();
            try {
                const errors = (0, express_validator_1.validationResult)(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }
                // Obtenha os dados do usuário a partir do corpo da requisição
                const { name, username, password, data_nasc } = req.body;
                // Verifique se o e-mail já está sendo usado
                const userCheck = yield client.query('SELECT * FROM clientes WHERE username = $1', [username]);
                if (userCheck.rows.length > 0) {
                    return res.status(400).json({ error: 'O e-mail já está em uso' });
                }
                // Use bcrypt para criptografar a senha
                const hashedPassword = yield bcrypt_1.default.hash(password, 10);
                // Começa a transação
                yield client.query('BEGIN');
                // Adicione o usuário ao banco de dados
                const query = 'INSERT INTO clientes (name, username, password, data_nasc) VALUES ($1, $2, $3, $4) RETURNING id';
                const userResult = yield client.query(query, [name, username, hashedPassword, data_nasc]);
                // Aqui, estamos recebendo o ID do usuário recém-criado.
                const userId = userResult.rows[0].id;
                // Exclua o token antigo do banco de dados, se houver
                yield client.query('DELETE FROM email_verifications WHERE user_id = $1', [userId]);
                // Gere um novo token seguro
                const token = (0, crypto_1.randomBytes)(32).toString('hex');
                // Defina a data de expiração para 1 hora a partir de agora
                const expiresAt = new Date();
                expiresAt.setTime(expiresAt.getTime() + 1 * 60 * 60 * 1000);
                // Insira o novo token no banco de dados
                yield client.query('INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)', [userId, token, expiresAt]);
                // Encerra a transação
                yield client.query('COMMIT');
                // Gere a URL de verificação
                const verificationUrl = `${req.protocol}://${req.get('host')}/usuarios/verificar-email/${token}`;
                // Use a função getEmailVerificationTemplate para gerar o corpo do email
                const emailBody = `
        <html>
          <body>
            <h1>Bem-vindo ao Horóscopo App</h1>
            <p>Por favor, verifique seu endereço de e-mail clicando no link abaixo:</p>
            <a href="${verificationUrl}">Verificar email</a>
          </body>
        </html>
      `;
                // Envie o email de verificação
                yield (0, mail_config_1.sendEmail)(username, 'Verifique seu endereço de email', emailBody);
                return res.status(200).json({ message: "Registro bem-sucedido! Verifique o seu e-mail." });
            }
            catch (err) {
                // Se algo der errado, faz o rollback da transação
                yield client.query('ROLLBACK');
                return res.status(500).json({ error: err.toString() });
            }
            finally {
                client.release();
            }
        });
    }
    verifyEmail(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const token = req.params.token;
            const client = yield this.dbClient.connect();
            try {
                // Verifique se o token existe no banco de dados
                const { rows } = yield this.dbClient.queryWithParams(client, 'SELECT * FROM email_verifications WHERE token = $1 AND expires_at > NOW()', [token]);
                const verification = rows[0];
                if (!verification) {
                    return res.status(400).send({ message: 'Token de verificação inválido ou expirado' });
                }
                // Verifique o email do usuário
                yield this.dbClient.queryWithParams(client, 'UPDATE clientes SET email_verified = TRUE WHERE id = $1', [verification.user_id]);
                // Remova o token do banco de dados
                yield this.dbClient.queryWithParams(client, 'DELETE FROM email_verifications WHERE id = $1', [verification.id]);
                return res.status(200).send({ message: 'Email verificado com sucesso' });
            }
            finally {
                client.release();
            }
        });
    }
    login(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const client = yield this.dbClient.connect();
            try {
                const errors = (0, express_validator_1.validationResult)(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }
                // Obtenha os dados de login do usuário a partir do corpo da requisição
                const { username, password } = req.body;
                // Recupere o usuário do banco de dados
                const query = 'SELECT * FROM clientes WHERE username = $1';
                const result = yield this.dbClient.queryWithParams(client, query, [username]);
                if (result.rows.length === 0) {
                    // Não existe usuário com o username fornecido
                    return res.status(401).json({ message: "Login falhou. Usuário ou senha inválidos." });
                }
                const user = result.rows[0];
                // Inserir a verificação de e-mail aqui
                if (!user.email_verified) {
                    return res.status(401).json({ message: "Por favor, verifique seu endereço de email." });
                }
                // Compare a senha fornecida com a senha do usuário
                const passwordMatches = yield bcrypt_1.default.compare(password, user.password);
                if (!passwordMatches) {
                    // Senha fornecida não corresponde à senha do usuário
                    return res.status(401).json({ message: "Login falhou. Usuário ou senha inválidos." });
                }
                // O login foi bem-sucedido
                return res.status(200).json({ message: "Login bem-sucedido!" });
            }
            finally {
                client.release();
            }
        });
    }
    updateName(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const { username, newName } = req.body;
            const client = yield this.dbClient.connect();
            try {
                const userCheck = yield this.dbClient.queryWithParams(client, 'SELECT * FROM clientes WHERE username = $1', [username]);
                if (userCheck.rows.length === 0) {
                    return res.status(404).json({ error: 'Usuário não encontrado' });
                }
                const query = 'UPDATE clientes SET name = $1 WHERE username = $2';
                yield this.dbClient.queryWithParams(client, query, [newName, username]);
                return res.status(200).json({ message: 'Nome atualizado com sucesso!' });
            }
            finally {
                client.release();
            }
        });
    }
    updateDOB(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const { username, newDOB } = req.body;
            const client = yield this.dbClient.connect();
            try {
                const userCheck = yield this.dbClient.queryWithParams(client, 'SELECT * FROM clientes WHERE username = $1', [username]);
                if (userCheck.rows.length === 0) {
                    return res.status(404).json({ error: 'Usuário não encontrado' });
                }
                const query = 'UPDATE clientes SET data_nasc = $1 WHERE username = $2';
                yield this.dbClient.queryWithParams(client, query, [newDOB, username]);
                return res.status(200).json({ message: 'Data de nascimento atualizada com sucesso!' });
            }
            finally {
                client.release();
            }
        });
    }
    deleteAccount(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const { username } = req.body;
            const client = yield this.dbClient.connect();
            try {
                const userCheck = yield this.dbClient.queryWithParams(client, 'SELECT * FROM clientes WHERE username = $1', [username]);
                if (userCheck.rows.length === 0) {
                    return res.status(404).json({ error: 'Usuário não encontrado' });
                }
                const query = 'DELETE FROM clientes WHERE username = $1';
                yield this.dbClient.queryWithParams(client, query, [username]);
                return res.status(200).json({ message: 'Conta excluída com sucesso!' });
            }
            finally {
                client.release();
            }
        });
    }
}
exports.UserController = UserController;
