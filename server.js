const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const session = require('express-session');
const methodOverride = require('method-override');
const path = require('path');

const app = express();
const port = 3001;

const urlMongo = 'mongodb://127.0.0.1:27017';
const nomeBanco = 'sistemaLogin';
const dbName = 'trabalhador';
const collectionName = 'trabalhadores';

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname)));

app.use(session({
    secret: 'segredo-super-seguro',
    resave: false,
    saveUninitialized: true, 
}));

// Middleware para proteger rotas
function protegerRota(req, res, proximo) {
    if (req.session.usuario) {
        proximo();
    } else {
        res.redirect('/login');
    }
}

// Rotas de registro
app.get('/registro', (req, res) => {
    res.sendFile(__dirname + '/1registro.html');
});

app.post('/registro', async (req, res) => {
    const cliente = new MongoClient(urlMongo, { useUnifiedTopology: true });
    try {
        await cliente.connect();
        const banco = cliente.db(nomeBanco);
        const colecaoUsuarios = banco.collection('usuarios');

        const usuariosExistentes = await colecaoUsuarios.findOne({ usuario: req.body.usuario });

        if (usuariosExistentes) {
            res.send('Usuário já existe! Tente outro nome de usuário.');
        } else {
            const senhaCriptografada = await bcrypt.hash(req.body.senha, 10);
            await colecaoUsuarios.insertOne({ usuario: req.body.usuario, senha: senhaCriptografada });
            res.redirect('/login');
        }
    } catch (erro) {
        res.send('Erro ao registrar o usuário.');
    } finally {
        cliente.close();
    }
});

// Rotas de login
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/1login.html');
});

app.post('/login', async (req, res) => {
    const cliente = new MongoClient(urlMongo, { useUnifiedTopology: true });
    try {
        await cliente.connect();
        const banco = cliente.db(nomeBanco);
        const colecaoUsuarios = banco.collection('usuarios');

        const usuario = await colecaoUsuarios.findOne({ usuario: req.body.usuario });

        if (usuario && await bcrypt.compare(req.body.senha, usuario.senha)) {
            req.session.usuario = req.body.usuario;
            res.redirect('/bemvindo');
        } else {
            res.redirect('/erro');
        }
    } catch (erro) {
        res.send('Erro ao realizar login.');
    } finally {
        cliente.close();
    }
});

// Rota de boas-vindas
app.get('/bemvindo', protegerRota, (req, res) => {
    res.sendFile(__dirname + '/1bemvindo.html');
});

// Rota de erro
app.get('/erro', (req, res) => {
    res.sendFile(__dirname + '/1erro.html');
});

// Rota de logout
app.get('/sair', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.send('Erro ao sair!');
        }
        res.redirect('/login');
    });
});


app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
