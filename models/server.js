const express = require('express');
const https = require('https');
const fs = require('fs');
const ejs = require('ejs');
const session = require('express-session');
const { error } = require('console');
const path = require('path');
const mongosse = require('mongoose');
const bycrypt = require('bcrypt');

class Server {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 5000;  
        this.middlewares();
        this.listen();
    }

    conectMongo(){
        mongosse.connect('mongodb://localhost:27017/Usuarios2025',)
        let = Shema = mongosse.Schema;
        const userShema = new Shema({
            user: String,
            pass: String,
            rol: String
        });
        this.userModel = mongosse.model('user', userShema); 
    }

    middlewares() {
        this.app.use(express.static('./public'));
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));

        this.app.set('view engine', 'ejs');
        this.app.set('trust proxy', 1);

        this.app.use(session({
            secret: 'clave',
            resave: false,
            saveUninitialized: true,
            cookie: { secure: false }
        }));

        this.routes();
    }

    routes() {
        this.app.get('/index', async(req, res) => {
            let user = req.body.user;
            let cont = req.body.pass;
            //validar base de datos
            let consulta = await this.userModel.find({user , user} );
            console.log(consulta);
            if (req.session.user) {
                if (req.session.rol === "admin") {
                    res.render('index', {nombre : req.session.user});
                } else {
                    res.render('index', {nombre : req.session.user});
                }
            } else {
                res.status(401).render('error', { mensaje: 'Datos incorrectos. Inténtalo de nuevo.' });
            }  
        });
        this.app.get('/single', (req, res) => {
            if (req.session.user) {
                if (req.session.rol === "admin") {
                    res.render('single', {user : req.session.user});
                } else {
                    res.render('single', {user : req.session.user});
                }
            } else {
                res.sendFile(path.join(__dirname,'../public/single.html'));
            }  
        });

        this.app.post('/login', async (req, res) => {
            let User = req.body.username;
            let Password = req.body.password;
            //Cifrar la contraseña
            let salt = bycrypt.genSaltSync(12);
            let hashCont = bycrypt.hashSync(Password, salt);
            console.log(hashCont);        
            // Buscar el usuario en la base de datos
            let consulta = await this.userModel.find({ usuario: User });
        
            if (consulta.length > 0) {  
                if (Password === consulta[0].pass) {  // Compara la contraseña
                    req.session.user = User;  
                    req.session.rol = consulta[0].rol;  // Asignar el rol desde la base de datos
                    res.render('index', { nombre: User });                  } else {
                    res.status(401).render('error', { mensaje: 'Contraseña incorrecta. Inténtalo de nuevo.' });
                }
            } else {
                res.status(401).render('error', { mensaje: 'Usuario no encontrado. Inténtalo de nuevo.' });
            }
        });
        

        this.app.post('/error', (req, res) => {
            res.status(404).render('error', { mensaje: 'Página no encontrada' });
        });
    }

    listen() {
        https.createServer({
            cert: fs.readFileSync('cert.crt'),
            key: fs.readFileSync('private.key')
        }, this.app).listen(this.port, () => {
            console.log('https://127.0.0.1:' + this.port);
        });
    }
}

module.exports = Server;
