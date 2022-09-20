/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./src/app.module.ts":
/*!***************************!*\
  !*** ./src/app.module.ts ***!
  \***************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const pedidos_module_1 = __webpack_require__(/*! ./pedidos/pedidos.module */ "./src/pedidos/pedidos.module.ts");
const auth_module_1 = __webpack_require__(/*! ./auth/auth.module */ "./src/auth/auth.module.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const restaurantes_module_1 = __webpack_require__(/*! ./restaurantes/restaurantes.module */ "./src/restaurantes/restaurantes.module.ts");
let AppModule = class AppModule {
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                envFilePath: '.env',
                isGlobal: true,
            }),
            mongoose_1.MongooseModule.forRootAsync({
                imports: [config_1.ConfigModule],
                useFactory: async (configService) => ({
                    uri: configService.get('MONGODB_URI'),
                }),
                inject: [config_1.ConfigService],
            }),
            auth_module_1.AuthModule,
            restaurantes_module_1.RestaurantesModule,
            pedidos_module_1.PedidosModule,
        ],
        controllers: [],
        providers: [],
    })
], AppModule);
exports.AppModule = AppModule;


/***/ }),

/***/ "./src/auth/auth.controller.ts":
/*!*************************************!*\
  !*** ./src/auth/auth.controller.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const auth_service_1 = __webpack_require__(/*! src/auth/auth.service */ "./src/auth/auth.service.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const criar_usuario_dto_1 = __webpack_require__(/*! src/auth/dto/criar-usuario.dto */ "./src/auth/dto/criar-usuario.dto.ts");
const usuario_decorator_1 = __webpack_require__(/*! ../helpers/usuario.decorator */ "./src/helpers/usuario.decorator.ts");
const usuario_schema_1 = __webpack_require__(/*! src/auth/schema/usuario.schema */ "./src/auth/schema/usuario.schema.ts");
const auth_1 = __webpack_require__(/*! src/auth/helper/auth */ "./src/auth/helper/auth.ts");
const usuarios_service_1 = __webpack_require__(/*! ./usuarios.service */ "./src/auth/usuarios.service.ts");
const efetuar_login_dto_1 = __webpack_require__(/*! ./dto/efetuar-login.dto */ "./src/auth/dto/efetuar-login.dto.ts");
let AuthController = class AuthController {
    constructor(usuariosService, authService) {
        this.usuariosService = usuariosService;
        this.authService = authService;
    }
    async regitro(userDTO) {
        await this.usuariosService.criarUsuario(userDTO);
    }
    async login(userDTO) {
        const user = await this.usuariosService.buscarUsuarioPorEmailSenha(userDTO);
        const payload = (0, auth_1.criarPayloadDoUsuario)(user);
        const token = await this.authService.criarTokenJWT(payload);
        return { user, token };
    }
    async ping(user) {
        return user;
    }
};
__decorate([
    (0, common_1.Post)('registro'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_a = typeof criar_usuario_dto_1.CriarUsuarioDTO !== "undefined" && criar_usuario_dto_1.CriarUsuarioDTO) === "function" ? _a : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "regitro", null);
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof efetuar_login_dto_1.EfetuarLoginDTO !== "undefined" && efetuar_login_dto_1.EfetuarLoginDTO) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Get)('/ping'),
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _c : Object]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], AuthController.prototype, "ping", null);
AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    (0, swagger_1.ApiTags)('Auth'),
    __metadata("design:paramtypes", [typeof (_e = typeof usuarios_service_1.UsuariosService !== "undefined" && usuarios_service_1.UsuariosService) === "function" ? _e : Object, typeof (_f = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _f : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ "./src/auth/auth.module.ts":
/*!*********************************!*\
  !*** ./src/auth/auth.module.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./src/auth/auth.controller.ts");
const jwt_strategy_1 = __webpack_require__(/*! ./strategies/jwt.strategy */ "./src/auth/strategies/jwt.strategy.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./src/auth/auth.service.ts");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const usuario_schema_1 = __webpack_require__(/*! ./schema/usuario.schema */ "./src/auth/schema/usuario.schema.ts");
const usuarios_service_1 = __webpack_require__(/*! ./usuarios.service */ "./src/auth/usuarios.service.ts");
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            mongoose_1.MongooseModule.forFeature([{ schema: usuario_schema_1.UsuarioSchema, name: usuario_schema_1.Usuario.name }]),
            jwt_1.JwtModule.register({
                secret: process.env.JWT_KEY,
                signOptions: { expiresIn: process.env.JWT_EXPIRES },
            }),
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, usuarios_service_1.UsuariosService, jwt_strategy_1.JwtStrategy],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ "./src/auth/auth.service.ts":
/*!**********************************!*\
  !*** ./src/auth/auth.service.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const usuarios_service_1 = __webpack_require__(/*! ./usuarios.service */ "./src/auth/usuarios.service.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
let AuthService = class AuthService {
    constructor(userService, jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }
    async criarTokenJWT(payload) {
        return this.jwtService.sign(payload);
    }
    async validarUsuario(payload) {
        return await this.userService.buscarUsuarioPeloEmailDoPayload(payload);
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof usuarios_service_1.UsuariosService !== "undefined" && usuarios_service_1.UsuariosService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),

/***/ "./src/auth/dto/criar-usuario.dto.ts":
/*!*******************************************!*\
  !*** ./src/auth/dto/criar-usuario.dto.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CriarUsuarioDTO = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CriarUsuarioDTO {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CriarUsuarioDTO.prototype, "nome", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CriarUsuarioDTO.prototype, "password", void 0);
__decorate([
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], CriarUsuarioDTO.prototype, "email", void 0);
exports.CriarUsuarioDTO = CriarUsuarioDTO;


/***/ }),

/***/ "./src/auth/dto/efetuar-login.dto.ts":
/*!*******************************************!*\
  !*** ./src/auth/dto/efetuar-login.dto.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EfetuarLoginDTO = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class EfetuarLoginDTO {
}
__decorate([
    (0, class_validator_1.IsEmail)(),
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], EfetuarLoginDTO.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], EfetuarLoginDTO.prototype, "password", void 0);
exports.EfetuarLoginDTO = EfetuarLoginDTO;


/***/ }),

/***/ "./src/auth/helper/auth.ts":
/*!*********************************!*\
  !*** ./src/auth/helper/auth.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validarPassword = exports.criarPayloadDoUsuario = exports.LimparUsuario = void 0;
const bcrypt = __webpack_require__(/*! bcrypt */ "bcrypt");
const LimparUsuario = (user) => {
    user.password = undefined;
    return user;
};
exports.LimparUsuario = LimparUsuario;
const criarPayloadDoUsuario = (user) => {
    return {
        id: user._id.toString(),
        email: user.email,
        dono: user.dono,
    };
};
exports.criarPayloadDoUsuario = criarPayloadDoUsuario;
const validarPassword = async (password, userPassword) => {
    return await bcrypt.compare(password, userPassword);
};
exports.validarPassword = validarPassword;


/***/ }),

/***/ "./src/auth/schema/usuario.schema.ts":
/*!*******************************************!*\
  !*** ./src/auth/schema/usuario.schema.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsuarioSchema = exports.Usuario = void 0;
const abstract_schema_1 = __webpack_require__(/*! src/database/abstract.schema */ "./src/database/abstract.schema.ts");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const bcrypt = __webpack_require__(/*! bcrypt */ "bcrypt");
let Usuario = class Usuario extends abstract_schema_1.AbstractDocument {
};
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Usuario.prototype, "nome", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Usuario.prototype, "password", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Usuario.prototype, "email", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Boolean, default: false }),
    __metadata("design:type", Boolean)
], Usuario.prototype, "dono", void 0);
Usuario = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false })
], Usuario);
exports.Usuario = Usuario;
exports.UsuarioSchema = mongoose_1.SchemaFactory.createForClass(Usuario);
exports.UsuarioSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    this['password'] = await bcrypt.hash(this['password'], 10);
    return next();
});


/***/ }),

/***/ "./src/auth/strategies/jwt.strategy.ts":
/*!*********************************************!*\
  !*** ./src/auth/strategies/jwt.strategy.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtStrategy = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "passport-jwt");
const auth_service_1 = __webpack_require__(/*! ../auth.service */ "./src/auth/auth.service.ts");
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    constructor(authService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_KEY,
        });
        this.authService = authService;
    }
    async validate(payload, done) {
        const user = await this.authService.validarUsuario(payload);
        if (!user) {
            return done(new common_1.HttpException('Acesso negado', common_1.HttpStatus.UNAUTHORIZED), false);
        }
        return done(null, user, payload.iat);
    }
};
JwtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object])
], JwtStrategy);
exports.JwtStrategy = JwtStrategy;


/***/ }),

/***/ "./src/auth/usuarios.service.ts":
/*!**************************************!*\
  !*** ./src/auth/usuarios.service.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsuariosService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const mongoose_1 = __webpack_require__(/*! mongoose */ "mongoose");
const mongoose_2 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const auth_1 = __webpack_require__(/*! src/auth/helper/auth */ "./src/auth/helper/auth.ts");
let UsuariosService = class UsuariosService {
    constructor(userModel) {
        this.userModel = userModel;
    }
    async criarUsuario(criarUsuarioDTO) {
        const { email } = criarUsuarioDTO;
        const usuario = await this.userModel.findOne({ email });
        if (usuario) {
            throw new common_1.HttpException('Email já existe!', common_1.HttpStatus.UNPROCESSABLE_ENTITY);
        }
        const createdUser = new this.userModel(criarUsuarioDTO);
        await createdUser.save();
        return (0, auth_1.LimparUsuario)(createdUser);
    }
    async buscarUsuarioPorEmailSenha(userDTO) {
        const { email, password } = userDTO;
        const user = await this.userModel.findOne({ email });
        if (!user || (await (0, auth_1.validarPassword)(password, user.password)) === false) {
            throw new common_1.HttpException('Credenciais não encontradas', common_1.HttpStatus.UNPROCESSABLE_ENTITY);
        }
        return (0, auth_1.LimparUsuario)(user);
    }
    async buscarUsuarioPeloEmailDoPayload(payload) {
        const { email } = payload;
        return await this.userModel.findOne({ email });
    }
};
UsuariosService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_2.InjectModel)('Usuario')),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_1.Model !== "undefined" && mongoose_1.Model) === "function" ? _a : Object])
], UsuariosService);
exports.UsuariosService = UsuariosService;


/***/ }),

/***/ "./src/database/abstract.schema.ts":
/*!*****************************************!*\
  !*** ./src/database/abstract.schema.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AbstractDocument = void 0;
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
let AbstractDocument = class AbstractDocument {
};
AbstractDocument = __decorate([
    (0, mongoose_1.Schema)()
], AbstractDocument);
exports.AbstractDocument = AbstractDocument;


/***/ }),

/***/ "./src/guards/manager.guard.ts":
/*!*************************************!*\
  !*** ./src/guards/manager.guard.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ManagerGuard = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let ManagerGuard = class ManagerGuard {
    constructor() { }
    canActivate(context) {
        const request = context.switchToHttp().getRequest();
        const user = request.user;
        if (user.dono) {
            return true;
        }
        throw new common_1.HttpException('Acesso negado para usuarios NÃO Administradores', common_1.HttpStatus.UNAUTHORIZED);
    }
};
ManagerGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], ManagerGuard);
exports.ManagerGuard = ManagerGuard;


/***/ }),

/***/ "./src/helpers/pedidos.ts":
/*!********************************!*\
  !*** ./src/helpers/pedidos.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidarStatusAtualPedido = exports.orderStatus = void 0;
exports.orderStatus = [
    { status: 'Solicitado', usuario: 'cliente' },
    { status: 'Cancelou', usuario: 'cliente' },
    { status: 'Processando', usuario: 'dono' },
    { status: 'Em Rota', usuario: 'dono' },
    { status: 'Entregue', usuario: 'dono' },
    { status: 'Recebido', usuario: 'cliente' },
];
var STATUS;
(function (STATUS) {
    STATUS["Solicitado"] = "Solicitado";
    STATUS["Processando"] = "Processando";
    STATUS["Recebido"] = "Recebido";
})(STATUS || (STATUS = {}));
const ValidarStatusAtualPedido = (dono, newStatus, oldStatus) => {
    if (oldStatus == STATUS.Recebido) {
        return false;
    }
    if (oldStatus == STATUS.Solicitado && newStatus == STATUS.Processando && dono) {
        return true;
    }
    const usuarioType = dono ? 'dono' : 'cliente';
    for (const [idx, oStatus] of exports.orderStatus.entries()) {
        if (oStatus.status == oldStatus) {
            const nextStatus = exports.orderStatus[idx + 1];
            if (nextStatus.status == newStatus && nextStatus.usuario == usuarioType) {
                return true;
            }
        }
    }
    return false;
};
exports.ValidarStatusAtualPedido = ValidarStatusAtualPedido;


/***/ }),

/***/ "./src/helpers/usuario.decorator.ts":
/*!******************************************!*\
  !*** ./src/helpers/usuario.decorator.ts ***!
  \******************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsuarioDecorator = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.UsuarioDecorator = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
});


/***/ }),

/***/ "./src/helpers/validators.ts":
/*!***********************************!*\
  !*** ./src/helpers/validators.ts ***!
  \***********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateID = void 0;
const bson_1 = __webpack_require__(/*! bson */ "bson");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const validateID = (id) => {
    if (!bson_1.ObjectID.isValid(id)) {
        throw new common_1.HttpException('Formato do "identificador" inválido', common_1.HttpStatus.BAD_REQUEST);
    }
};
exports.validateID = validateID;


/***/ }),

/***/ "./src/pedidos/dto/pedidos.dto.ts":
/*!****************************************!*\
  !*** ./src/pedidos/dto/pedidos.dto.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ChangePedidoStatusDTO = exports.CreatePedidoDTO = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const pedidos_1 = __webpack_require__(/*! src/helpers/pedidos */ "./src/helpers/pedidos.ts");
const status = pedidos_1.orderStatus.map((item) => item.status);
class ProdutoPedido {
}
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], ProdutoPedido.prototype, "produtoID", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: Number, minimum: 0, maximum: 99 }),
    __metadata("design:type", Number)
], ProdutoPedido.prototype, "preco", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: Number, minimum: 0, maximum: 99 }),
    (0, class_validator_1.IsInt)(),
    (0, class_validator_1.Min)(1),
    (0, class_validator_1.Max)(99),
    __metadata("design:type", Number)
], ProdutoPedido.prototype, "quantidade", void 0);
class Endereco {
}
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Endereco.prototype, "logradouro", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Endereco.prototype, "bairro", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], Endereco.prototype, "cep", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], Endereco.prototype, "complemento", void 0);
class CreatePedidoDTO {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.ValidateNested)({ each: true }),
    (0, swagger_1.ApiProperty)({ type: [ProdutoPedido] }),
    (0, class_transformer_1.Type)(() => ProdutoPedido),
    __metadata("design:type", Array)
], CreatePedidoDTO.prototype, "produtos", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], CreatePedidoDTO.prototype, "restauranteID", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.ValidateNested)({ each: true }),
    (0, swagger_1.ApiProperty)({ type: Endereco }),
    (0, class_transformer_1.Type)(() => Endereco),
    __metadata("design:type", Endereco)
], CreatePedidoDTO.prototype, "endereco", void 0);
exports.CreatePedidoDTO = CreatePedidoDTO;
class ChangePedidoStatusDTO {
}
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsIn)(status),
    (0, class_validator_1.NotEquals)('Solicitado'),
    __metadata("design:type", String)
], ChangePedidoStatusDTO.prototype, "status", void 0);
exports.ChangePedidoStatusDTO = ChangePedidoStatusDTO;


/***/ }),

/***/ "./src/pedidos/pedidos.controller.ts":
/*!*******************************************!*\
  !*** ./src/pedidos/pedidos.controller.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PedidosController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const pedidos_service_1 = __webpack_require__(/*! ./pedidos.service */ "./src/pedidos/pedidos.service.ts");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const usuario_schema_1 = __webpack_require__(/*! src/auth/schema/usuario.schema */ "./src/auth/schema/usuario.schema.ts");
const pedidos_dto_1 = __webpack_require__(/*! src/pedidos/dto/pedidos.dto */ "./src/pedidos/dto/pedidos.dto.ts");
const usuario_decorator_1 = __webpack_require__(/*! src/helpers/usuario.decorator */ "./src/helpers/usuario.decorator.ts");
let PedidosController = class PedidosController {
    constructor(pedidosService) {
        this.pedidosService = pedidosService;
    }
    async criarPedido(criarPedidoDTO, user) {
        return await this.pedidosService.criarPedido(user, criarPedidoDTO);
    }
    async buscarTodosPedidosDoRestaurante(user, restauranteID) {
        return await this.pedidosService.buscarTodosPedidosDoRestaurante(user, restauranteID);
    }
    async buscarPedidosPeloID(user, pedidoID) {
        return await this.pedidosService.buscarPedidoPeloID(user, pedidoID);
    }
    async atualizarStatus(user, pedidoID, changeStatusDTO) {
        return await this.pedidosService.atualizarStatus(user, pedidoID, changeStatusDTO);
    }
};
__decorate([
    (0, common_1.Post)(),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, usuario_decorator_1.UsuarioDecorator)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_a = typeof pedidos_dto_1.CreatePedidoDTO !== "undefined" && pedidos_dto_1.CreatePedidoDTO) === "function" ? _a : Object, typeof (_b = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], PedidosController.prototype, "criarPedido", null);
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiQuery)({ name: 'restauranteID', required: false }),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __param(1, (0, common_1.Query)('restauranteID')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _c : Object, Object]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], PedidosController.prototype, "buscarTodosPedidosDoRestaurante", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __param(1, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_e = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _e : Object, String]),
    __metadata("design:returntype", Promise)
], PedidosController.prototype, "buscarPedidosPeloID", null);
__decorate([
    (0, common_1.Patch)(':id'),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __param(1, (0, common_1.Param)('id')),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_f = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _f : Object, String, typeof (_g = typeof pedidos_dto_1.ChangePedidoStatusDTO !== "undefined" && pedidos_dto_1.ChangePedidoStatusDTO) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], PedidosController.prototype, "atualizarStatus", null);
PedidosController = __decorate([
    (0, swagger_1.ApiTags)('Pedidos'),
    (0, common_1.Controller)('pedidos'),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __metadata("design:paramtypes", [typeof (_h = typeof pedidos_service_1.PedidosService !== "undefined" && pedidos_service_1.PedidosService) === "function" ? _h : Object])
], PedidosController);
exports.PedidosController = PedidosController;


/***/ }),

/***/ "./src/pedidos/pedidos.module.ts":
/*!***************************************!*\
  !*** ./src/pedidos/pedidos.module.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PedidosModule = void 0;
const auth_module_1 = __webpack_require__(/*! src/auth/auth.module */ "./src/auth/auth.module.ts");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const pedidos_controller_1 = __webpack_require__(/*! ./pedidos.controller */ "./src/pedidos/pedidos.controller.ts");
const pedidos_service_1 = __webpack_require__(/*! ./pedidos.service */ "./src/pedidos/pedidos.service.ts");
const restaurantes_module_1 = __webpack_require__(/*! src/restaurantes/restaurantes.module */ "./src/restaurantes/restaurantes.module.ts");
const pedidos_schema_1 = __webpack_require__(/*! ./schema/pedidos.schema */ "./src/pedidos/schema/pedidos.schema.ts");
let PedidosModule = class PedidosModule {
};
PedidosModule = __decorate([
    (0, common_1.Module)({
        imports: [
            mongoose_1.MongooseModule.forFeature([{ name: pedidos_schema_1.Pedido.name, schema: pedidos_schema_1.PedidoSchema }]),
            auth_module_1.AuthModule,
            restaurantes_module_1.RestaurantesModule,
        ],
        controllers: [pedidos_controller_1.PedidosController],
        providers: [pedidos_service_1.PedidosService],
    })
], PedidosModule);
exports.PedidosModule = PedidosModule;


/***/ }),

/***/ "./src/pedidos/pedidos.service.ts":
/*!****************************************!*\
  !*** ./src/pedidos/pedidos.service.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PedidosService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
const produtos_service_1 = __webpack_require__(/*! src/restaurantes/produtos.service */ "./src/restaurantes/produtos.service.ts");
const restaurantes_service_1 = __webpack_require__(/*! ../restaurantes/restaurantes.service */ "./src/restaurantes/restaurantes.service.ts");
const validators_1 = __webpack_require__(/*! src/helpers/validators */ "./src/helpers/validators.ts");
let PedidosService = class PedidosService {
    constructor(PedidoModel, produtosService, restaurantesService) {
        this.PedidoModel = PedidoModel;
        this.produtosService = produtosService;
        this.restaurantesService = restaurantesService;
    }
    async criarPedido(user, createDTO) {
        const { restauranteID, endereco, produtos } = createDTO;
        const restaurante = await this.restaurantesService.buscarRestaurantePorId(restauranteID);
        if (!restaurante) {
            throw new common_1.HttpException('Restaurante não encontrado', common_1.HttpStatus.NOT_FOUND);
        }
        const criarPedido = {
            usuarioID: user._id,
            produtos: produtos,
            preco_total: 0,
            endereco,
            status: 'Solicitado',
            historico_status: [{ status: 'Solicitado' }],
            restauranteID: restauranteID,
            criado_em: Date.now(),
        };
        const { _id } = await this.PedidoModel.create(criarPedido);
        let Pedido = await this.PedidoModel.findById(_id);
        const preco_total = produtos.reduce((acc, produtoObj) => {
            const _preco = produtoObj.preco * produtoObj.quantidade;
            return acc + _preco;
        }, 0);
        await Pedido.updateOne({ preco_total });
        Pedido = await this.PedidoModel.findById(_id);
        return Pedido;
    }
    async buscarTodosPedidosDoRestaurante(user, restauranteID) {
        if (user.dono) {
            if (restauranteID) {
                return await this.PedidoModel.find({
                    restaurant: restauranteID,
                })
                    .populate('usuarioID')
                    .sort({ createdAt: -1 });
            }
            const restaurantList = await this.restaurantesService.buscarRestaurantes(user);
            const ids = restaurantList.map((restaurant) => restaurant._id);
            return await this.PedidoModel.find({
                restauranteID: { $in: ids },
            })
                .populate('restauranteID')
                .sort({ createdAt: -1 });
        }
        return this.PedidoModel.find({
            _id: user._id,
        })
            .populate('restauranteID')
            .sort({ createdAt: -1 });
    }
    async buscarPedidoPeloID(user, PedidoID) {
        (0, validators_1.validateID)(PedidoID);
        const Pedido = await this.PedidoModel.findById({ _id: PedidoID })
            .populate('produtos.produtoID')
            .populate('restauranteID')
            .populate('usuarioID');
        if (!Pedido) {
            throw new common_1.HttpException('Pedido não encontrado', common_1.HttpStatus.NOT_FOUND);
        }
        await this.validateUserAccessToPedido(user, Pedido);
        return Pedido;
    }
    async atualizarStatus(user, PedidoID, changeStatusDTO) {
        const _pedido = await this.buscarPedidoPeloID(user, PedidoID);
        const { status: novoStatus } = changeStatusDTO;
        const { historico_status } = _pedido;
        historico_status.push({
            status: novoStatus,
            criado_em: new Date(),
        });
        await this.PedidoModel.findById(_pedido._id).updateOne(Object.assign(Object.assign({}, changeStatusDTO), { historico_status }));
        return await this.buscarPedidoPeloID(user, PedidoID);
    }
    async validateUserAccessToPedido(user, Pedido) {
        if (user.dono) {
            if (!(await this.restaurantesService.validarAcessoRestaurante(Pedido.restauranteID._id.toString(), user))) {
                throw new common_1.HttpException('Restaurante não encontrado', common_1.HttpStatus.FORBIDDEN);
            }
            return true;
        }
        if (Pedido.usuarioID._id != user._id) {
            throw new common_1.HttpException('Pedido não encontrado', common_1.HttpStatus.FORBIDDEN);
        }
        return true;
    }
};
PedidosService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)('Pedido')),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof produtos_service_1.ProdutosService !== "undefined" && produtos_service_1.ProdutosService) === "function" ? _b : Object, typeof (_c = typeof restaurantes_service_1.RestaurantesService !== "undefined" && restaurantes_service_1.RestaurantesService) === "function" ? _c : Object])
], PedidosService);
exports.PedidosService = PedidosService;


/***/ }),

/***/ "./src/pedidos/schema/historico.schema.ts":
/*!************************************************!*\
  !*** ./src/pedidos/schema/historico.schema.ts ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HistoricoPedidoSchema = exports.HistoricoPedido = void 0;
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
let HistoricoPedido = class HistoricoPedido {
};
__decorate([
    (0, mongoose_1.Prop)({ type: String, default: '' }),
    __metadata("design:type", String)
], HistoricoPedido.prototype, "status", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Date, default: Date.now() }),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], HistoricoPedido.prototype, "criado_em", void 0);
HistoricoPedido = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false, _id: false })
], HistoricoPedido);
exports.HistoricoPedido = HistoricoPedido;
exports.HistoricoPedidoSchema = mongoose_1.SchemaFactory.createForClass(HistoricoPedido);


/***/ }),

/***/ "./src/pedidos/schema/pedidos.schema.ts":
/*!**********************************************!*\
  !*** ./src/pedidos/schema/pedidos.schema.ts ***!
  \**********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PedidoSchema = exports.Pedido = void 0;
const abstract_schema_1 = __webpack_require__(/*! src/database/abstract.schema */ "./src/database/abstract.schema.ts");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
const usuario_schema_1 = __webpack_require__(/*! src/auth/schema/usuario.schema */ "./src/auth/schema/usuario.schema.ts");
const restaurante_schema_1 = __webpack_require__(/*! src/restaurantes/schema/restaurante.schema */ "./src/restaurantes/schema/restaurante.schema.ts");
const historico_schema_1 = __webpack_require__(/*! ./historico.schema */ "./src/pedidos/schema/historico.schema.ts");
const produtos_pedido_schema_1 = __webpack_require__(/*! ./produtos-pedido.schema */ "./src/pedidos/schema/produtos-pedido.schema.ts");
class Endereco {
}
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Endereco.prototype, "logradouro", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Endereco.prototype, "bairro", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Endereco.prototype, "cep", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Endereco.prototype, "complemento", void 0);
let Pedido = class Pedido extends abstract_schema_1.AbstractDocument {
};
__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.default.Schema.Types.ObjectId, ref: 'Usuario' }),
    __metadata("design:type", typeof (_a = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _a : Object)
], Pedido.prototype, "usuarioID", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.default.Schema.Types.ObjectId, ref: 'Restaurante' }),
    __metadata("design:type", typeof (_b = typeof restaurante_schema_1.Restaurante !== "undefined" && restaurante_schema_1.Restaurante) === "function" ? _b : Object)
], Pedido.prototype, "restauranteID", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Pedido.prototype, "status", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: [{ type: historico_schema_1.HistoricoPedidoSchema, ref: historico_schema_1.HistoricoPedido.name }] }),
    __metadata("design:type", Array)
], Pedido.prototype, "historico_status", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", Endereco)
], Pedido.prototype, "endereco", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Pedido.prototype, "preco_total", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: [{ type: produtos_pedido_schema_1.ProdutosPedidoSchema, ref: produtos_pedido_schema_1.ProdutosPedido.name }] }),
    __metadata("design:type", Array)
], Pedido.prototype, "produtos", void 0);
Pedido = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false, timestamps: true })
], Pedido);
exports.Pedido = Pedido;
exports.PedidoSchema = mongoose_1.SchemaFactory.createForClass(Pedido);


/***/ }),

/***/ "./src/pedidos/schema/produtos-pedido.schema.ts":
/*!******************************************************!*\
  !*** ./src/pedidos/schema/produtos-pedido.schema.ts ***!
  \******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProdutosPedidoSchema = exports.ProdutosPedido = void 0;
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
const produto_schema_1 = __webpack_require__(/*! src/restaurantes/schema/produto.schema */ "./src/restaurantes/schema/produto.schema.ts");
let ProdutosPedido = class ProdutosPedido {
};
__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.default.Schema.Types.ObjectId, ref: 'Produto' }),
    __metadata("design:type", typeof (_a = typeof produto_schema_1.Produto !== "undefined" && produto_schema_1.Produto) === "function" ? _a : Object)
], ProdutosPedido.prototype, "produtoID", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], ProdutosPedido.prototype, "preco", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], ProdutosPedido.prototype, "quantidade", void 0);
ProdutosPedido = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false, _id: false })
], ProdutosPedido);
exports.ProdutosPedido = ProdutosPedido;
exports.ProdutosPedidoSchema = mongoose_1.SchemaFactory.createForClass(ProdutosPedido);


/***/ }),

/***/ "./src/restaurantes/dto/atualizar-restaurante.dto.ts":
/*!***********************************************************!*\
  !*** ./src/restaurantes/dto/atualizar-restaurante.dto.ts ***!
  \***********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AtualizarRestauranteDTO = void 0;
const criar_restaurante_dto_1 = __webpack_require__(/*! ./criar-restaurante.dto */ "./src/restaurantes/dto/criar-restaurante.dto.ts");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
class AtualizarRestauranteDTO extends (0, swagger_1.PartialType)(criar_restaurante_dto_1.CriarRestauranteDTO) {
}
exports.AtualizarRestauranteDTO = AtualizarRestauranteDTO;


/***/ }),

/***/ "./src/restaurantes/dto/criar-produtos.dto.ts":
/*!****************************************************!*\
  !*** ./src/restaurantes/dto/criar-produtos.dto.ts ***!
  \****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CriarRestauranteProdutoDTO = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CriarRestauranteProdutoDTO {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.MaxLength)(50),
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], CriarRestauranteProdutoDTO.prototype, "nome", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: String }),
    (0, class_validator_1.MaxLength)(100),
    __metadata("design:type", String)
], CriarRestauranteProdutoDTO.prototype, "descricao", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], CriarRestauranteProdutoDTO.prototype, "imagem", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, swagger_1.ApiProperty)({ type: Number }),
    __metadata("design:type", Number)
], CriarRestauranteProdutoDTO.prototype, "preco", void 0);
exports.CriarRestauranteProdutoDTO = CriarRestauranteProdutoDTO;


/***/ }),

/***/ "./src/restaurantes/dto/criar-restaurante.dto.ts":
/*!*******************************************************!*\
  !*** ./src/restaurantes/dto/criar-restaurante.dto.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CriarRestauranteDTO = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
class Endereco {
}
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Endereco.prototype, "logradouro", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Endereco.prototype, "bairro", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], Endereco.prototype, "cep", void 0);
__decorate([
    (0, swagger_1.ApiProperty)(),
    __metadata("design:type", String)
], Endereco.prototype, "complemento", void 0);
class CriarRestauranteDTO {
}
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.MaxLength)(50),
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], CriarRestauranteDTO.prototype, "nome", void 0);
__decorate([
    (0, class_validator_1.MaxLength)(100),
    (0, swagger_1.ApiProperty)({ type: String }),
    __metadata("design:type", String)
], CriarRestauranteDTO.prototype, "descricao", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.ValidateNested)({ each: true }),
    (0, swagger_1.ApiProperty)({ type: Endereco }),
    (0, class_transformer_1.Type)(() => Endereco),
    __metadata("design:type", Endereco)
], CriarRestauranteDTO.prototype, "endereco", void 0);
exports.CriarRestauranteDTO = CriarRestauranteDTO;


/***/ }),

/***/ "./src/restaurantes/produtos.service.ts":
/*!**********************************************!*\
  !*** ./src/restaurantes/produtos.service.ts ***!
  \**********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProdutosService = void 0;
const mongoose_1 = __webpack_require__(/*! mongoose */ "mongoose");
const mongoose_2 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const validators_1 = __webpack_require__(/*! src/helpers/validators */ "./src/helpers/validators.ts");
const produto_schema_1 = __webpack_require__(/*! ./schema/produto.schema */ "./src/restaurantes/schema/produto.schema.ts");
let ProdutosService = class ProdutosService {
    constructor(produtoModel) {
        this.produtoModel = produtoModel;
    }
    async criarProduto(restauranteID, produtoDTO) {
        const criarProduto = Object.assign(Object.assign({}, produtoDTO), { restauranteID: restauranteID });
        return await this.produtoModel.create(criarProduto);
    }
    async buscarProdutosDoRestaurante(restauranteID, produtoID) {
        if (produtoID) {
            (0, validators_1.validateID)(produtoID);
            return await this.produtoModel.find({
                _id: produtoID,
                restaurantID: restauranteID,
            });
        }
        return await this.produtoModel.find({ restauranteID: restauranteID });
    }
    async atualizarProduto(produtoID, produtoDTO) {
        (0, validators_1.validateID)(produtoID);
        const produto = await this.produtoModel.findById(produtoID);
        if (!produto) {
            throw new common_1.HttpException('Produto não encontrado.', common_1.HttpStatus.NOT_FOUND);
        }
        await produto.updateOne(produtoDTO);
        return await this.produtoModel
            .findById(produtoID)
            .populate('restauranteID');
    }
    async deletarProdutodoRestaurante(restauranteID, produtoID) {
        const produto = await this.produtoModel.findOneAndDelete({
            _id: produtoID,
            restaurantID: restauranteID,
        });
        return produto;
    }
    async validarProdutosParaOMesmoRestaurante(produtos, restauranteID) {
        for (const [oProduto] of produtos.entries()) {
            await (0, validators_1.validateID)(oProduto.produto);
            const produto = await this.produtoModel.findById(oProduto.produto);
            if (!produto || produto.restauranteID._id.toString() != restauranteID) {
                return false;
            }
        }
        return true;
    }
};
ProdutosService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_2.InjectModel)(produto_schema_1.Produto.name)),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_1.Model !== "undefined" && mongoose_1.Model) === "function" ? _a : Object])
], ProdutosService);
exports.ProdutosService = ProdutosService;


/***/ }),

/***/ "./src/restaurantes/restaurantes.controller.ts":
/*!*****************************************************!*\
  !*** ./src/restaurantes/restaurantes.controller.ts ***!
  \*****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RestaurantesController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const restaurantes_service_1 = __webpack_require__(/*! ./restaurantes.service */ "./src/restaurantes/restaurantes.service.ts");
const produtos_service_1 = __webpack_require__(/*! src/restaurantes/produtos.service */ "./src/restaurantes/produtos.service.ts");
const manager_guard_1 = __webpack_require__(/*! src/guards/manager.guard */ "./src/guards/manager.guard.ts");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const usuario_decorator_1 = __webpack_require__(/*! src/helpers/usuario.decorator */ "./src/helpers/usuario.decorator.ts");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const criar_restaurante_dto_1 = __webpack_require__(/*! ./dto/criar-restaurante.dto */ "./src/restaurantes/dto/criar-restaurante.dto.ts");
const criar_produtos_dto_1 = __webpack_require__(/*! src/restaurantes/dto/criar-produtos.dto */ "./src/restaurantes/dto/criar-produtos.dto.ts");
const atualizar_restaurante_dto_1 = __webpack_require__(/*! ./dto/atualizar-restaurante.dto */ "./src/restaurantes/dto/atualizar-restaurante.dto.ts");
const usuario_schema_1 = __webpack_require__(/*! src/auth/schema/usuario.schema */ "./src/auth/schema/usuario.schema.ts");
let RestaurantesController = class RestaurantesController {
    constructor(restauranteService, produtosService) {
        this.restauranteService = restauranteService;
        this.produtosService = produtosService;
    }
    async criarRestaurante(restauranteDTO, user) {
        return this.restauranteService.criarRestaurante(restauranteDTO, user);
    }
    async buscarTodosRestaurantes(user) {
        return this.restauranteService.buscarRestaurantes(user);
    }
    async atualizarRestaurante(user, restauranteID, restauranteDTO) {
        return this.restauranteService.atualizarRestaurante(restauranteID, restauranteDTO);
    }
    async deletarRestaurante(user, restauranteID) {
        return this.restauranteService.deletarRestaurantePorID(restauranteID);
    }
    async buscarRestaurante(user, restauranteID) {
        return await this.restauranteService.buscarRestaurantePorId(restauranteID);
    }
    async criarProduto(produtoDTO, restauranteID) {
        return this.produtosService.criarProduto(restauranteID, produtoDTO);
    }
    async buscarProdutos(restauranteID) {
        return this.produtosService.buscarProdutosDoRestaurante(restauranteID);
    }
    async buscarProduto(restauranteID, produto) {
        return this.produtosService.buscarProdutosDoRestaurante(restauranteID, produto);
    }
    async deletarProdutoDoRestaurante(restauranteID, produtoID, user) {
        return this.produtosService.deletarProdutodoRestaurante(restauranteID, produtoID);
    }
};
__decorate([
    (0, common_1.Post)(),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt'), manager_guard_1.ManagerGuard),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, usuario_decorator_1.UsuarioDecorator)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_a = typeof criar_restaurante_dto_1.CriarRestauranteDTO !== "undefined" && criar_restaurante_dto_1.CriarRestauranteDTO) === "function" ? _a : Object, typeof (_b = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _b : Object]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], RestaurantesController.prototype, "criarRestaurante", null);
__decorate([
    (0, common_1.Get)(),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], RestaurantesController.prototype, "buscarTodosRestaurantes", null);
__decorate([
    (0, common_1.Patch)(':id'),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __param(1, (0, common_1.Param)('id')),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_e = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _e : Object, String, typeof (_f = typeof atualizar_restaurante_dto_1.AtualizarRestauranteDTO !== "undefined" && atualizar_restaurante_dto_1.AtualizarRestauranteDTO) === "function" ? _f : Object]),
    __metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], RestaurantesController.prototype, "atualizarRestaurante", null);
__decorate([
    (0, common_1.Delete)(':id'),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __param(1, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_h = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _h : Object, String]),
    __metadata("design:returntype", Promise)
], RestaurantesController.prototype, "deletarRestaurante", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, common_1.HttpCode)(200),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, usuario_decorator_1.UsuarioDecorator)()),
    __param(1, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_j = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _j : Object, String]),
    __metadata("design:returntype", Promise)
], RestaurantesController.prototype, "buscarRestaurante", null);
__decorate([
    (0, common_1.Post)(':id/produtos'),
    (0, common_1.HttpCode)(201),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_k = typeof criar_produtos_dto_1.CriarRestauranteProdutoDTO !== "undefined" && criar_produtos_dto_1.CriarRestauranteProdutoDTO) === "function" ? _k : Object, String]),
    __metadata("design:returntype", Promise)
], RestaurantesController.prototype, "criarProduto", null);
__decorate([
    (0, common_1.Get)(':id/produtos'),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], RestaurantesController.prototype, "buscarProdutos", null);
__decorate([
    (0, common_1.Get)(':id/produtos/:produto'),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Param)('produto')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_m = typeof Promise !== "undefined" && Promise) === "function" ? _m : Object)
], RestaurantesController.prototype, "buscarProduto", null);
__decorate([
    (0, common_1.Delete)(':id/produtos/:produto'),
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Param)('produto')),
    __param(2, (0, usuario_decorator_1.UsuarioDecorator)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, typeof (_o = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _o : Object]),
    __metadata("design:returntype", Promise)
], RestaurantesController.prototype, "deletarProdutoDoRestaurante", null);
RestaurantesController = __decorate([
    (0, common_1.Controller)('restaurantes'),
    (0, swagger_1.ApiTags)('Restaurantes'),
    __metadata("design:paramtypes", [typeof (_p = typeof restaurantes_service_1.RestaurantesService !== "undefined" && restaurantes_service_1.RestaurantesService) === "function" ? _p : Object, typeof (_q = typeof produtos_service_1.ProdutosService !== "undefined" && produtos_service_1.ProdutosService) === "function" ? _q : Object])
], RestaurantesController);
exports.RestaurantesController = RestaurantesController;


/***/ }),

/***/ "./src/restaurantes/restaurantes.module.ts":
/*!*************************************************!*\
  !*** ./src/restaurantes/restaurantes.module.ts ***!
  \*************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RestaurantesModule = void 0;
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const restaurantes_controller_1 = __webpack_require__(/*! ./restaurantes.controller */ "./src/restaurantes/restaurantes.controller.ts");
const restaurantes_service_1 = __webpack_require__(/*! ./restaurantes.service */ "./src/restaurantes/restaurantes.service.ts");
const restaurante_schema_1 = __webpack_require__(/*! ./schema/restaurante.schema */ "./src/restaurantes/schema/restaurante.schema.ts");
const auth_module_1 = __webpack_require__(/*! src/auth/auth.module */ "./src/auth/auth.module.ts");
const produto_schema_1 = __webpack_require__(/*! ./schema/produto.schema */ "./src/restaurantes/schema/produto.schema.ts");
const produtos_service_1 = __webpack_require__(/*! ./produtos.service */ "./src/restaurantes/produtos.service.ts");
let RestaurantesModule = class RestaurantesModule {
};
RestaurantesModule = __decorate([
    (0, common_1.Module)({
        imports: [
            mongoose_1.MongooseModule.forFeature([
                { schema: restaurante_schema_1.RestauranteSchema, name: restaurante_schema_1.Restaurante.name },
                { schema: produto_schema_1.ProdutoSchema, name: produto_schema_1.Produto.name },
            ]),
            auth_module_1.AuthModule
        ],
        controllers: [restaurantes_controller_1.RestaurantesController],
        providers: [restaurantes_service_1.RestaurantesService, produtos_service_1.ProdutosService],
        exports: [restaurantes_service_1.RestaurantesService, produtos_service_1.ProdutosService],
    })
], RestaurantesModule);
exports.RestaurantesModule = RestaurantesModule;


/***/ }),

/***/ "./src/restaurantes/restaurantes.service.ts":
/*!**************************************************!*\
  !*** ./src/restaurantes/restaurantes.service.ts ***!
  \**************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var RestaurantesService_1, _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RestaurantesService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const mongoose_1 = __webpack_require__(/*! mongoose */ "mongoose");
const mongoose_2 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const validators_1 = __webpack_require__(/*! src/helpers/validators */ "./src/helpers/validators.ts");
let RestaurantesService = RestaurantesService_1 = class RestaurantesService {
    constructor(restauranteModel) {
        this.restauranteModel = restauranteModel;
        this.logger = new common_1.Logger(RestaurantesService_1.name);
    }
    async buscarRestaurantes(user) {
        this.logger.warn('user : [' + user + ']');
        return await this.restauranteModel.find({});
    }
    async buscarRestaurantePorId(restauranteID) {
        return await this.restauranteModel.findById({ _id: restauranteID });
    }
    async criarRestaurante(restauranteDTO, usuario) {
        const criarRestaurante = Object.assign({ donoID: usuario }, restauranteDTO);
        return await this.restauranteModel.create(criarRestaurante);
    }
    async atualizarRestaurante(restauranteID, restauranteDTO) {
        (0, validators_1.validateID)(restauranteID);
        const restaurant = await this.restauranteModel.findById(restauranteID);
        if (!restaurant) {
            throw new common_1.HttpException("Restaurante não encontrado", common_1.HttpStatus.NOT_FOUND);
        }
        await restaurant.updateOne(restauranteDTO);
        return await this.restauranteModel.findById(restauranteID);
    }
    async deletarRestaurantePorID(restauranteID) {
        const restaurante = await this.restauranteModel.findOneAndDelete({
            _id: restauranteID,
        });
        if (!restaurante) {
            throw new common_1.HttpException('Restaurante não encontrado', common_1.HttpStatus.NOT_FOUND);
        }
        return restaurante;
    }
    async validarAcessoRestaurante(restauranteID, user) {
        const restaurantList = await this.buscarRestaurantes(user);
        return restaurantList.some((elem) => elem._id.toString() == restauranteID);
    }
};
RestaurantesService = RestaurantesService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_2.InjectModel)('Restaurante')),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_1.Model !== "undefined" && mongoose_1.Model) === "function" ? _a : Object])
], RestaurantesService);
exports.RestaurantesService = RestaurantesService;


/***/ }),

/***/ "./src/restaurantes/schema/produto.schema.ts":
/*!***************************************************!*\
  !*** ./src/restaurantes/schema/produto.schema.ts ***!
  \***************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProdutoSchema = exports.Produto = void 0;
const abstract_schema_1 = __webpack_require__(/*! src/database/abstract.schema */ "./src/database/abstract.schema.ts");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
const restaurante_schema_1 = __webpack_require__(/*! src/restaurantes/schema/restaurante.schema */ "./src/restaurantes/schema/restaurante.schema.ts");
let Produto = class Produto extends abstract_schema_1.AbstractDocument {
};
__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.default.Schema.Types.ObjectId, ref: 'Restaurante' }),
    __metadata("design:type", typeof (_a = typeof restaurante_schema_1.Restaurante !== "undefined" && restaurante_schema_1.Restaurante) === "function" ? _a : Object)
], Produto.prototype, "restauranteID", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Produto.prototype, "nome", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Produto.prototype, "descricao", void 0);
__decorate([
    (0, mongoose_1.Prop)(),
    __metadata("design:type", String)
], Produto.prototype, "imagem", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Number, default: 0 }),
    __metadata("design:type", Number)
], Produto.prototype, "preco", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: Date, default: Date.now() }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], Produto.prototype, "criado_em", void 0);
Produto = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false })
], Produto);
exports.Produto = Produto;
exports.ProdutoSchema = mongoose_1.SchemaFactory.createForClass(Produto);


/***/ }),

/***/ "./src/restaurantes/schema/restaurante.schema.ts":
/*!*******************************************************!*\
  !*** ./src/restaurantes/schema/restaurante.schema.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RestauranteSchema = exports.Restaurante = void 0;
const abstract_schema_1 = __webpack_require__(/*! src/database/abstract.schema */ "./src/database/abstract.schema.ts");
const mongoose_1 = __webpack_require__(/*! @nestjs/mongoose */ "@nestjs/mongoose");
const mongoose_2 = __webpack_require__(/*! mongoose */ "mongoose");
const usuario_schema_1 = __webpack_require__(/*! src/auth/schema/usuario.schema */ "./src/auth/schema/usuario.schema.ts");
class Endereco {
}
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Endereco.prototype, "logradouro", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Endereco.prototype, "bairro", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Endereco.prototype, "cep", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Endereco.prototype, "complemento", void 0);
let Restaurante = class Restaurante extends abstract_schema_1.AbstractDocument {
};
__decorate([
    (0, mongoose_1.Prop)({ type: mongoose_2.default.Schema.Types.ObjectId, ref: 'Usuario' }),
    __metadata("design:type", typeof (_a = typeof usuario_schema_1.Usuario !== "undefined" && usuario_schema_1.Usuario) === "function" ? _a : Object)
], Restaurante.prototype, "donoID", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Restaurante.prototype, "nome", void 0);
__decorate([
    (0, mongoose_1.Prop)({ type: String }),
    __metadata("design:type", String)
], Restaurante.prototype, "descricao", void 0);
__decorate([
    (0, mongoose_1.Prop)({ schema: [Endereco] }),
    __metadata("design:type", Endereco)
], Restaurante.prototype, "endereco", void 0);
Restaurante = __decorate([
    (0, mongoose_1.Schema)({ versionKey: false })
], Restaurante);
exports.Restaurante = Restaurante;
exports.RestauranteSchema = mongoose_1.SchemaFactory.createForClass(Restaurante);


/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/mongoose":
/*!***********************************!*\
  !*** external "@nestjs/mongoose" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/mongoose");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@nestjs/swagger":
/*!**********************************!*\
  !*** external "@nestjs/swagger" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),

/***/ "bcrypt":
/*!*************************!*\
  !*** external "bcrypt" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "bson":
/*!***********************!*\
  !*** external "bson" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("bson");

/***/ }),

/***/ "class-transformer":
/*!************************************!*\
  !*** external "class-transformer" ***!
  \************************************/
/***/ ((module) => {

module.exports = require("class-transformer");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "dotenv/config":
/*!********************************!*\
  !*** external "dotenv/config" ***!
  \********************************/
/***/ ((module) => {

module.exports = require("dotenv/config");

/***/ }),

/***/ "helmet":
/*!*************************!*\
  !*** external "helmet" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("helmet");

/***/ }),

/***/ "mongoose":
/*!***************************!*\
  !*** external "mongoose" ***!
  \***************************/
/***/ ((module) => {

module.exports = require("mongoose");

/***/ }),

/***/ "passport-jwt":
/*!*******************************!*\
  !*** external "passport-jwt" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!*********************!*\
  !*** ./src/main.ts ***!
  \*********************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
__webpack_require__(/*! dotenv/config */ "dotenv/config");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./src/app.module.ts");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const helmet_1 = __webpack_require__(/*! helmet */ "helmet");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.useGlobalPipes(new common_1.ValidationPipe());
    const options = new swagger_1.DocumentBuilder()
        .setTitle('Documentação da API')
        .setDescription('Delivery REST API')
        .setVersion('1.0.0')
        .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' })
        .build();
    const document = swagger_1.SwaggerModule.createDocument(app, options);
    swagger_1.SwaggerModule.setup('/', app, document);
    app.use((0, helmet_1.default)());
    app.enableCors();
    const configService = app.get(config_1.ConfigService);
    await app.listen(configService.get('PORT'));
}
bootstrap();

})();

/******/ })()
;