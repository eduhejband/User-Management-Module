import { Pool, PoolClient } from 'pg';
import * as pg from 'pg';
export class DbClient {
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      user: process.env.DB_USER,
      host: process.env.DB_HOST,
      database: process.env.DB_NAME,
      password: process.env.DB_PASSWORD,
      port: Number(process.env.DB_PORT),
    });
  }

  // Exponha o método connect para obter um cliente de conexão única
  public async connect(): Promise<PoolClient> {
    const client = await this.pool.connect();
    return client;
  }

  // Use declarações preparadas para evitar injeção de SQL
  // Observe que agora este método aceita um cliente como parâmetro
  public async queryWithParams(client: PoolClient, text: string, params: Array<any>): Promise<pg.QueryResult> {
    return client.query(text, params);
  }

  public getClient(): pg.Pool {
    return this.pool;
  }
   
}
  // Não precisamos mais do método getClient

