import { App } from './App';
import dotenv from 'dotenv';

dotenv.config();
const port = Number(process.env.PORT) || 3010;
new App().listen(port);
