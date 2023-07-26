import { Application, Request, Response,NextFunction  } from 'express';
import { check, validationResult } from 'express-validator';
import { DbClient } from './DbClient';
import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { sendEmail } from './mail_config';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as JwtStrategy, ExtractJwt, VerifiedCallback } from 'passport-jwt';
import { QueryResult } from 'pg';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken'; // substitua por sua própria configuração de secret
import { jwtSecret } from './config';

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
          'DELETE FROM clientes WHERE email_verified = FALSE AND created_at < NOW() - INTERVAL \'1 hour\'',
          []
        );
      } finally {
        client.release();
      }
    }, 1000 * 60 * 60); // executa a cada hora

    app.use(passport.initialize());
    passport.use(new GoogleStrategy({
      clientID: process.env.CLIENT_ID!,
      clientSecret: process.env.SECRET_KEY!,
      callbackURL: process.env.CALLBACK_URL
    },
    this.googleAuthCallback.bind(this))); // Método de callback para tratar a resposta do Google

    passport.use(new JwtStrategy({
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: process.env.JWT_SECRET
    }, async function(this: UserController, jwt_payload: any, done: VerifiedCallback) {
        const client = await this.dbClient.connect();
        try {
            const result = await this.dbClient.queryWithParams(
                client,
                'SELECT * FROM clientes WHERE id = $1',
                [jwt_payload.id]
            );
            if (result.rows.length > 0) {
                return done(null, result.rows[0]);
            } else {
                return done(null, false);
            }
        } catch (err) {
            return done(err, false);
        } finally {
            client.release();
        }
    }.bind(this)));
  }
  

  private configureRoutes(app: Application): void {

    const loginLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 50, // limit each IP to 100 requests per windowMs
      message: 'Too many login attempts from this IP, please try again after 15 minutes.'
    });

    app.post('/cadastro', [
      check('name').notEmpty().withMessage('Full name is required'),
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password')
      .isLength({ min: 7 }).withMessage('Password must be at least 7 chars long')
      .matches(/\d/).withMessage('Password must contain a number')
      .matches(/[a-z]/i).withMessage('Password must contain a letter'),
      check('data_nasc').notEmpty().withMessage('Date of birth is required'),
      check('terms_accepted').isBoolean().withMessage('Terms acceptance is required'),
      check('privacy_accepted').isBoolean().withMessage('Privacy acceptance is required')
    ], this.register.bind(this));
    
    app.route('/login')
      .post([
        check('username').notEmpty().withMessage('Username is required'),
        check('password').notEmpty().withMessage('Password is required')
      ], this.login.bind(this));

    app.post('/update-name', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password')
      .isLength({ min: 7 }).withMessage('Password must be at least 7 chars long')
      .matches(/\d/).withMessage('Password must contain a number')
      .matches(/[a-z]/i).withMessage('Password must contain a letter'),
      check('newName').notEmpty().withMessage('New name is required')
    ], this.updateName.bind(this));

    app.post('/update-dob', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password')
      .isLength({ min: 7 }).withMessage('Password must be at least 7 chars long')
      .matches(/\d/).withMessage('Password must contain a number')
      .matches(/[a-z]/i).withMessage('Password must contain a letter'),
      check('newDOB').notEmpty().withMessage('New date of birth is required')
    ], this.updateDOB.bind(this));

    app.delete('/delete-account', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
      check('password')
      .isLength({ min: 7 }).withMessage('Password must be at least 7 chars long')
      .matches(/\d/).withMessage('Password must contain a number')
      .matches(/[a-z]/i).withMessage('Password must contain a letter')
    ], this.deleteAccount.bind(this));

    app.post('/reset-password/:token', [
      check('password')
      .isLength({ min: 7 }).withMessage('Password must be at least 7 chars long')
      .matches(/\d/).withMessage('Password must contain a number')
      .matches(/[a-z]/i).withMessage('Password must contain a letter')
    ], this.resetPassword.bind(this));

    app.post('/request-password-reset', [
      check('username').isEmail().withMessage('Invalid e-mail format'),
    ], this.requestPasswordReset.bind(this));

    app.route('/usuarios/verificar-email/:token')
    .get(this.verifyEmail.bind(this));

    app.post('/register-whatsapp-number', [
      passport.authenticate('jwt', { session: false }),
      check('phoneNumber').notEmpty().withMessage('Phone number is required')
    ], this.registerWhatsAppNumber.bind(this));

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
    app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), this.googleAuthSuccess.bind(this));
    app.post('/insert-birthdate-auth', [
      check('birthdate').notEmpty().withMessage('Data de nascimento é obrigatória'),
    ], this.insertBirthdateAuth.bind(this));

    app.get('/path', this.authenticateJWT, (req, res) => {
      res.json({message: "Você está autorizado!"});
    });

    app.route('/logout')
      .post([
        this.authenticateJWT
      ], this.logout.bind(this));
  }

  private authenticateJWT(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
      
    if (authHeader) {
      const token = authHeader.split(' ')[1];
  
      jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
          return res.sendStatus(403);
        }
  
        req.user = user;
        next();
      });
    } else {
      res.sendStatus(401);
    }
};

async logout(req: Request, res: Response) {
  // como o JWT é stateless, para fazer logout o cliente simplesmente descarta o token.
  res.sendStatus(200);
}

  // E então, adicione o método registerWhatsAppNumber no UserController
  private async registerWhatsAppNumber(req: Request, res: Response) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  
    const client = await this.dbClient.connect();
    try {
      await client.query('BEGIN'); // Inicia a transação
  
      const { username, phoneNumber } = req.body;
  
      const userCheckQuery = 'SELECT * FROM clientes WHERE username = $1';
      const userCheckValues = [username];
      const userCheckResult = await this.dbClient.queryWithParams(client, userCheckQuery, userCheckValues);
  
      if (userCheckResult.rowCount === 0) {
        return res.status(400).json({ error: 'User not found' });
      }
  
      const updateQuery = 'UPDATE clientes SET phone_number = $1 WHERE username = $2';
      const updateValues = [phoneNumber, username];
      await this.dbClient.queryWithParams(client, updateQuery, updateValues);
  
      await client.query('COMMIT'); // Finaliza a transação
  
      res.status(200).json({ message: 'Phone number updated successfully' });
    } catch (err) {
      console.error(err);
      await client.query('ROLLBACK'); // Desfaz a transação em caso de erro
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }
  
  private async googleAuthCallback(accessToken: string, refreshToken: string, profile: any, cb: Function) {
    const client = await this.dbClient.connect();
    try {
      await client.query('BEGIN'); // Inicia a transação
  
      const response = await axios.get(`https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${accessToken}`);
      if (response.status !== 200) {
        throw new Error('Token de acesso inválido');
      }
  
      const { displayName, emails } = profile;
      const email = emails[0].value;
  
      const userCheckQuery = 'SELECT * FROM clientes WHERE username = $1';
      const userCheckValues = [email];
      const userCheckResult: QueryResult = await this.dbClient.queryWithParams(client, userCheckQuery, userCheckValues);
  
      if (userCheckResult.rows.length === 0) {
        const query = 'INSERT INTO clientes (username, email_verified, terms_accepted, privacy_accepted, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id';
        const queryValues = [email, true, true, true, new Date()];
        const userResult: QueryResult = await this.dbClient.queryWithParams(client, query, queryValues);
  
        const userId = userResult.rows[0].id;
      }
  
      await client.query('COMMIT'); // Finaliza a transação
  
      cb(null, profile);
    } catch (err) {
      console.error(err);
      await client.query('ROLLBACK'); // Desfaz a transação em caso de erro
      cb(err);
    } finally {
      client.release();
    }
  }
  
  private async googleAuthSuccess(req: Request, res: Response) {
    const client = await this.dbClient.connect();
    try {
      await client.query('BEGIN'); // Inicia a transação
  
      if (!req.user || !('id' in req.user)) {
        res.redirect('/error');
        return;
      }
  
      const userId = req.user.id;
  
      const userCheckQuery = 'SELECT data_nasc FROM clientes WHERE id = $1';
      const userCheckValues = [userId];
      const userCheckResult: QueryResult = await this.dbClient.queryWithParams(client, userCheckQuery, userCheckValues);
  
      const birthDate = userCheckResult.rows[0].data_nasc;
  
      if (!birthDate) {
        res.redirect('/insert-birthdate-auth');
      } else {
        res.redirect('/');
      }
  
      await client.query('COMMIT'); // Finaliza a transação
    } catch (err) {
      console.error(err);
      await client.query('ROLLBACK'); // Desfaz a transação em caso de erro
      res.status(500).send('Erro interno do servidor');
    } finally {
      client.release();
    }
  }
   
  private async insertBirthdateAuth(req: Request, res: Response) {
    const client = await this.dbClient.connect();
    try {
      if (!req.user || !('id' in req.user)) {
        // Se o usuário não estiver autenticado corretamente, redirecione para uma página de erro ou faça o tratamento apropriado
        res.redirect('/error');
        return;
      }
  
      const userId = req.user.id;
      const { birthdate } = req.body;
  
      // Atualize a tabela "clientes" com a data de nascimento fornecida
      const updateQuery = 'UPDATE clientes SET data_nasc = $1 WHERE id = $2';
      const updateValues = [birthdate, userId];
      await this.dbClient.queryWithParams(client, updateQuery, updateValues);
  
      res.redirect('/');
    } catch (err) {
      console.error(err);
      res.status(500).send('Erro interno do servidor');
    } finally {
      client.release();
    }
  }
  
  

  private async register(req: Request, res: Response): Promise<Response> {
    const client = await this.dbClient.connect();
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
      // Obtenha os dados do usuário a partir do corpo da requisição
      const { name, username, password, data_nasc, terms_accepted, privacy_accepted } = req.body;
  
      // Verifica se os termos e política de privacidade foram aceitos
      if (!terms_accepted || !privacy_accepted) {
        return res.status(400).json({ error: 'Termos de serviço e política de privacidade devem ser aceitos' });
      }
  
      // Verifique se o e-mail já está sendo usado
      const userCheck = await client.query('SELECT * FROM clientes WHERE username = $1', [username]);
      if (userCheck.rowCount > 0) {
        return res.status(400).json({ error: 'O e-mail já está em uso' });
      }
  
      // Use bcrypt para criptografar a senha
      const hashedPassword = await bcrypt.hash(password, 10);
      
      let userResult;
      let token;

      try {
        // Iniciar transação
        await client.query('BEGIN');

        // Adicione o usuário ao banco de dados
        const query = 'INSERT INTO clientes (name, username, password, data_nasc, terms_accepted, privacy_accepted) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id';
        const values = [name, username, hashedPassword, data_nasc, terms_accepted, privacy_accepted];

        userResult = await client.query(query, values);

        // Aqui, estamos recebendo o ID do usuário recém-criado.
        const userId = userResult.rows[0].id;

        // Exclua o token antigo do banco de dados, se houver
        await client.query('DELETE FROM email_verifications WHERE user_id = $1', [userId]);

        // Gere um novo token seguro
        token = randomBytes(32).toString('hex');

        // Defina a data de expiração para 1 hora a partir de agora
        const expiresAt = new Date();
        expiresAt.setTime(expiresAt.getTime() + 1 * 60 * 60 * 1000);

        // Insira o novo token no banco de dados
        const insertTokenQuery = 'INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)';
        await client.query(insertTokenQuery, [userId, token, expiresAt]);

      } catch (err) {
        await client.query('ROLLBACK');
        return res.status(500).json({ error: 'Erro ao adicionar usuário ao banco de dados.' });
      }

      // Encerrar transação
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

  private async requestPasswordReset(req: Request, res: Response): Promise<Response> {
    const username = req.body.username;
  
    const client = await this.dbClient.connect();
  
    try {
      // Verifique se o username existe
      const userCheck = await client.query('SELECT * FROM clientes WHERE username = $1', [username]);
      const user = userCheck.rows[0];
      if (!user) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
      }
  
      // Gere um novo token de redefinição de senha
      const token = randomBytes(32).toString('hex');
  
      // Defina a data de expiração para 1 hora a partir de agora
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1);
  
      // Delete qualquer token existente para esse usuário
      await this.dbClient.queryWithParams(client, 'DELETE FROM email_verifications WHERE user_id = $1', [user.id]);
  
      // Insira o novo token no banco de dados
      await this.dbClient.queryWithParams(
        client,
        'INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [user.id, token, expiresAt]
      );
  
      // Gere a URL de redefinição de senha
      const resetUrl = `${req.protocol}://${req.get('host')}/usuarios/redefinir-senha/${token}`;
  
      // Gere o corpo do email
      const emailBody = `
        <html>
          <body>
            <h1>Redefinição de Senha</h1>
            <p>Por favor, redefina sua senha clicando no link abaixo:</p>
            <a href="${resetUrl}">Redefinir senha</a>
          </body>
        </html>
      `;
  
      // Envie o email de redefinição de senha
      await sendEmail(username, 'Redefinição de senha', emailBody);
  
      return res.status(200).json({ message: "Solicitação de redefinição de senha enviada! Verifique o seu e-mail." });
    } finally {
      client.release();
    }
  }
  
  private async resetPassword(req: Request, res: Response): Promise<Response> {
    const token = req.params.token;
    const newPassword = req.body.password;
  
    const client = await this.dbClient.connect();
  
    try {
      // Verifique se o token existe no banco de dados e ainda é válido
      const resetResult = await this.dbClient.queryWithParams(
        client,
        'SELECT * FROM email_verifications WHERE token = $1 AND expires_at > NOW()',
        [token]
      );
  
      const reset = resetResult.rows[0];
  
      if (!reset) {
        return res.status(400).json({ message: 'Token de redefinição de senha inválido ou expirado' });
      }
  
      // Use bcrypt para criptografar a nova senha
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      // Atualize a senha do usuário no banco de dados
      await this.dbClient.queryWithParams(
        client,
        'UPDATE clientes SET password = $1 WHERE id = $2',
        [hashedPassword, reset.user_id]
      );
  
      // Remova o token do banco de dados
      await this.dbClient.queryWithParams(
        client,
        'DELETE FROM email_verifications WHERE id = $1',
        [reset.id]
      );
  
      return res.status(200).json({ message: 'Senha redefinida com sucesso' });
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
  
      // Gerar um token de acesso
      const accessToken = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
    
      // O login foi bem-sucedido
      return res.status(200).json({ message: "Login bem-sucedido!", accessToken });
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
