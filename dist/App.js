"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.App = void 0;
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet")); // adicione esta linha
const express_rate_limit_1 = __importDefault(require("express-rate-limit")); // adicione esta linha
const UserController_1 = require("./UserController");
const HoroscopeController_1 = require("./HoroscopeController");
process.on('unhandledRejection', (reason, promise) => {
    console.log('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});
class App {
    constructor() {
        this.app = (0, express_1.default)();
        this.configureMiddleware();
        this.configureRoutes();
        console.log('App is running...');
    }
    configureMiddleware() {
        this.app.use((0, cors_1.default)());
        this.app.use(express_1.default.json());
        this.app.use(express_1.default.urlencoded({ extended: true }));
        // Use Helmet para adicionar cabeçalhos HTTP seguros
        this.app.use((0, helmet_1.default)());
        // Use limitação de taxa para evitar ataques de força bruta e DDoS
        this.app.use((0, express_rate_limit_1.default)({ windowMs: 15 * 60 * 1000, max: 100 }));
    }
    configureRoutes() {
        new UserController_1.UserController(this.app);
        new HoroscopeController_1.HoroscopeController(this.app);
    }
    listen(port) {
        this.app.listen(port, () => {
            console.log(`Server started at http://localhost:${port}`);
        });
    }
}
exports.App = App;
