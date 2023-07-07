import { Application, Request, Response } from 'express';
import { check, validationResult } from 'express-validator';
import { DbClient } from './DbClient';
import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { sendEmail } from './mail_config';


export class UserController {
  private dbClient: DbClient;

  constructor(app: Application) {
    this.dbClient = new DbClient();
    this.configureRoutes(app);
    setInterval(async () => {
      const client = await this.dbClient.connect();
      try {
        await this.dbClient.queryWithParams(
          client,
          'DELETE FROM clientes WHERE email_verified = FALSE AND created_at < NOW() - INTERVAL \'1 hour\'', []
        );
      } finally {
        client.release();
      }
    }, 1000 * 60 * 60); // executa a cada hora
  }
  

  private configureRoutes(app: Application): void {
    app.post('/cadastro', [
      check('name').notEmpty().withMessage('Full name is required'),
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long'),
      check('data_nasc').notEmpty().withMessage('Date of birth is required')
    ], this.register.bind(this));
    
    app.post('/login', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long')
    ], this.login.bind(this));

    app.post('/update-name', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long'),
      check('newName').notEmpty().withMessage('New name is required')
    ], this.updateName.bind(this));

    app.post('/update-dob', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long'),
      check('newDOB').notEmpty().withMessage('New date of birth is required')
    ], this.updateDOB.bind(this));

    app.post('/delete-account', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password').isLength({ min: 5 }).withMessage('Password must be at least 5 chars long')
    ], this.deleteAccount.bind(this));

    app.route('/usuarios/verificar-email/:token')
    .get(this.verifyEmail.bind(this));
  }

  private async register(req: Request, res: Response): Promise<Response> {
    const client = await this.dbClient.connect();
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Obtenha os dados do usuário a partir do corpo da requisição
      const { name, username, password, data_nasc } = req.body;

      // Verifique se o e-mail já está sendo usado
      const userCheck = await client.query('SELECT * FROM clientes WHERE username = $1', [username]);
      if (userCheck.rows.length > 0) {
        return res.status(400).json({ error: 'O e-mail já está em uso' });
      }

      // Use bcrypt para criptografar a senha
      const hashedPassword = await bcrypt.hash(password, 10);

      // Começa a transação
      await client.query('BEGIN');

      // Adicione o usuário ao banco de dados
      const query = 'INSERT INTO clientes (name, username, password, data_nasc) VALUES ($1, $2, $3, $4) RETURNING id';
      const userResult = await client.query(query, [name, username, hashedPassword, data_nasc]);

      // Aqui, estamos recebendo o ID do usuário recém-criado.
      const userId = userResult.rows[0].id;

      // Exclua o token antigo do banco de dados, se houver
      await client.query('DELETE FROM email_verifications WHERE user_id = $1', [userId]);

      // Gere um novo token seguro
      const token = randomBytes(32).toString('hex');

      // Defina a data de expiração para 1 hora a partir de agora
      const expiresAt = new Date();
      expiresAt.setTime(expiresAt.getTime() + 1 * 60 * 60 * 1000);

      // Insira o novo token no banco de dados
      await client.query(
        'INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [userId, token, expiresAt]
      );

      // Encerra a transação
      await client.query('COMMIT');

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
      await sendEmail(username, 'Verifique seu endereço de email', emailBody);

      return res.status(200).json({ message: "Registro bem-sucedido! Verifique o seu e-mail." });
    } catch (err) {
      // Se algo der errado, faz o rollback da transação
      await client.query('ROLLBACK');
      return res.status(500).json({ error: (err as Error).toString() });
    } finally {
      client.release();
    }
  }
  

  private async verifyEmail(req: Request, res: Response): Promise<Response> {
    const token = req.params.token;
    
    const client = await this.dbClient.connect();
  
    try {
      // Verifique se o token existe no banco de dados
      const { rows } = await this.dbClient.queryWithParams(
        client,
        'SELECT * FROM email_verifications WHERE token = $1 AND expires_at > NOW()',
        [token]
      );
      const verification = rows[0];
      if (!verification) {
        return res.status(400).send({ message: 'Token de verificação inválido ou expirado' });
      }
    
      // Verifique o email do usuário
      await this.dbClient.queryWithParams(
        client,
        'UPDATE clientes SET email_verified = TRUE WHERE id = $1',
        [verification.user_id]
      );
    
      // Remova o token do banco de dados
      await this.dbClient.queryWithParams(
        client,
        'DELETE FROM email_verifications WHERE id = $1',
        [verification.id]
      );
    
      return res.status(200).send({ message: 'Email verificado com sucesso' });
    } finally {
      client.release();
    }
  }
  
  private async login(req: Request, res: Response): Promise<Response> {
    const client = await this.dbClient.connect();
  
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      // Obtenha os dados de login do usuário a partir do corpo da requisição
      const { username, password } = req.body;
    
      // Recupere o usuário do banco de dados
      const query = 'SELECT * FROM clientes WHERE username = $1';
      const result = await this.dbClient.queryWithParams(client, query, [username]);
    
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
      const passwordMatches = await bcrypt.compare(password, user.password);
    
      if (!passwordMatches) {
        // Senha fornecida não corresponde à senha do usuário
        return res.status(401).json({ message: "Login falhou. Usuário ou senha inválidos." });
      }
    
      // O login foi bem-sucedido
      return res.status(200).json({ message: "Login bem-sucedido!" });
    } finally {
      client.release();
    }
  }
  
  private async updateName(req: Request, res: Response): Promise<Response> {
    const { username, newName } = req.body;
    
    const client = await this.dbClient.connect();
  
    try {
      const userCheck = await this.dbClient.queryWithParams(client, 'SELECT * FROM clientes WHERE username = $1', [username]);
      if (userCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }
    
      const query = 'UPDATE clientes SET name = $1 WHERE username = $2';
      await this.dbClient.queryWithParams(client, query, [newName, username]);
    
      return res.status(200).json({ message: 'Nome atualizado com sucesso!' });
    } finally {
      client.release();
    }
  }
  
  private async updateDOB(req: Request, res: Response): Promise<Response> {
    const { username, newDOB } = req.body;
    
    const client = await this.dbClient.connect();
  
    try {
      const userCheck = await this.dbClient.queryWithParams(client, 'SELECT * FROM clientes WHERE username = $1', [username]);
      if (userCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }
    
      const query = 'UPDATE clientes SET data_nasc = $1 WHERE username = $2';
      await this.dbClient.queryWithParams(client, query, [newDOB, username]);
    
      return res.status(200).json({ message: 'Data de nascimento atualizada com sucesso!' });
    } finally {
      client.release();
    }
  }
  
  private async deleteAccount(req: Request, res: Response): Promise<Response> {
    const { username } = req.body;
  
    const client = await this.dbClient.connect();
  
    try {
      const userCheck = await this.dbClient.queryWithParams(client, 'SELECT * FROM clientes WHERE username = $1', [username]);
      if (userCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }
    
      const query = 'DELETE FROM clientes WHERE username = $1';
      await this.dbClient.queryWithParams(client, query, [username]);
    
      return res.status(200).json({ message: 'Conta excluída com sucesso!' });
    } finally {
      client.release();
    }
  }
}  
