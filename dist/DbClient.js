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
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbClient = void 0;
const pg_1 = require("pg");
class DbClient {
    constructor() {
        this.pool = new pg_1.Pool({
            user: process.env.DB_USER,
            host: process.env.DB_HOST,
            database: process.env.DB_NAME,
            password: process.env.DB_PASSWORD,
            port: Number(process.env.DB_PORT),
        });
    }
    // Exponha o método connect para obter um cliente de conexão única
    connect() {
        return __awaiter(this, void 0, void 0, function* () {
            const client = yield this.pool.connect();
            return client;
        });
    }
    // Use declarações preparadas para evitar injeção de SQL
    // Observe que agora este método aceita um cliente como parâmetro
    queryWithParams(client, text, params) {
        return __awaiter(this, void 0, void 0, function* () {
            return client.query(text, params);
        });
    }
    getClient() {
        return this.pool;
    }
}
exports.DbClient = DbClient;
// Não precisamos mais do método getClient
