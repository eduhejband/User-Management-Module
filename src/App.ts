import express, { Application } from 'express';
import cors from 'cors';
import helmet from 'helmet'; // adicione esta linha
import rateLimit from 'express-rate-limit'; // adicione esta linha
import { UserController } from './UserController';
import { HoroscopeController } from './HoroscopeController';


process.on('unhandledRejection', (reason, promise) => {
  console.log('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

export class App {
  private app: Application;
  
  constructor() {
    this.app = express();
    this.configureMiddleware();
    this.configureRoutes();
    console.log('App is running...');
  }

  private configureMiddleware(): void {
    this.app.use(cors());
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    // Use Helmet para adicionar cabeçalhos HTTP seguros
    this.app.use(helmet());
    // Use limitação de taxa para evitar ataques de força bruta e DDoS
    this.app.use(rateLimit({windowMs: 15 * 60 * 1000, max: 100}));
  }

  private configureRoutes(): void {
    new UserController(this.app);
    new HoroscopeController(this.app);
  }

  public listen(port: number): void {
    this.app.listen(port, () => {
      console.log(`Server started at http://localhost:${port}`);
    });
  }

}
