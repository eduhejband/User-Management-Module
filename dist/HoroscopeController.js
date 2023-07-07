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
exports.HoroscopeController = void 0;
const axios_1 = __importDefault(require("axios"));
const DbClient_1 = require("./DbClient");
class HoroscopeController {
    constructor(app) {
        this.dbClient = new DbClient_1.DbClient();
        this.configureRoutes(app);
    }
    configureRoutes(app) {
        app.get('/horoscopo', this.getHoroscope.bind(this));
        console.log("Configuração de rotas concluída");
    }
    getHoroscope(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            const { username } = req.query;
            if (!username) {
                return res.status(400).send({ error: 'Usuário é obrigatório' });
            }
            try {
                const result = yield this.dbClient.getClient().query('SELECT * FROM clientes WHERE username = $1', [username]);
                console.log(`Resultado da query: ${JSON.stringify(result.rows)}`);
                if (result.rows.length === 0) {
                    return res.status(404).send({ error: 'Usuário não encontrado' });
                }
                console.log('Usuário encontrado, recuperando data de nascimento');
                const dataNascimento = result.rows[0].data_nasc;
                const dataNascimentoDate = new Date(dataNascimento);
                console.log(`Data de nascimento: ${dataNascimento}`);
                const day = dataNascimentoDate.getDate();
                const month = dataNascimentoDate.getMonth() + 1; //Em JS o mês começa com 0 logo tem que adicionar 1
                let signo = '';
                if ((month == 1 && day >= 20) || (month == 2 && day <= 18)) {
                    signo = 'aquario';
                }
                else if ((month == 2 && day >= 19) || (month == 3 && day <= 20)) {
                    signo = 'peixes';
                }
                else if ((month == 3 && day >= 21) || (month == 4 && day <= 19)) {
                    signo = 'aries';
                }
                else if ((month == 4 && day >= 20) || (month == 5 && day <= 20)) {
                    signo = 'touro';
                }
                else if ((month == 5 && day >= 21) || (month == 6 && day <= 21)) {
                    signo = 'gemeos';
                }
                else if ((month == 6 && day >= 22) || (month == 7 && day <= 22)) {
                    signo = 'cancer';
                }
                else if ((month == 7 && day >= 23) || (month == 8 && day <= 22)) {
                    signo = 'leao';
                }
                else if ((month == 8 && day >= 23) || (month == 9 && day <= 22)) {
                    signo = 'virgem';
                }
                else if ((month == 9 && day >= 23) || (month == 10 && day <= 22)) {
                    signo = 'libra';
                }
                else if ((month == 10 && day >= 23) || (month == 11 && day <= 21)) {
                    signo = 'escorpiao';
                }
                else if ((month == 11 && day >= 22) || (month == 12 && day <= 21)) {
                    signo = 'sagitario';
                }
                console.log(`Signo: ${signo}`);
                const token = process.env.API_TOKEN; // Substitua pelo seu token de API
                const characteristics = yield axios_1.default.get(`http://localhost:3001/characteristics/${signo}`, {
                    headers: { 'X-API-Key': token },
                });
                console.log(`Características: ${JSON.stringify(characteristics.data)}`);
                return res.send({
                    signo,
                    characteristics: characteristics.data,
                });
            }
            catch (err) {
                console.error(err);
                return res.status(500).send({ error: 'Erro ao buscar horóscopo' });
            }
        });
    }
}
exports.HoroscopeController = HoroscopeController;
