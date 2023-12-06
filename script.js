const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const port = 3000;

// Configurando o banco de dados usando o adapter FileSync
const adapter = new FileSync('db.json');
const db = low(adapter);

// Inicializando o banco de dados com uma tabela 'users' vazia
db.defaults({ users: [] }).write();

// Middleware para análise de JSON
app.use(bodyParser.json());

// Função para gerar token JWT
function generateToken(email) {
  return jwt.sign({ email }, 'secret', { expiresIn: '30m' });
}

// Middleware para autenticação do token
function authenticateToken(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ mensagem: 'Token não fornecido' });

  jwt.verify(token.replace('Bearer ', ''), 'secret', (err, user) => {
    if (err) return res.status(403).json({ mensagem: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Função para criar usuário
function createUser(nome, email, senha, telefones) {
  const hashedPassword = bcrypt.hashSync(senha, 10);
  const user = {
    id: uuidv4(),
    nome,
    email,
    senha: hashedPassword,
    telefones,
    dataCriacao: new Date(),
    dataAtualizacao: new Date(),
    ultimoLogin: new Date(),
    token: generateToken(email),
  };
  db.get('users').push(user).write();
  return user;
}

// Função para obter usuário pelo e-mail
function getUserByEmail(email) {
  return db.get('users').find({ email }).value();
}

// Rota de criação de usuário
app.post('/signup', (req, res) => {
  const { nome, email, senha, telefones } = req.body;

  if (!nome || !email || !senha || !telefones) {
    return res.status(400).json({ mensagem: 'Parâmetros inválidos' });
  }

  const existingUser = getUserByEmail(email);
  if (existingUser) {
    return res.status(409).json({ mensagem: 'E-mail já cadastrado' });
  }

  const newUser = createUser(nome, email, senha, telefones);
  res.status(201).json({
    id: newUser.id,
    data_criacao: newUser.dataCriacao,
    data_atualizacao: newUser.dataAtualizacao,
    ultimo_login: newUser.ultimoLogin,
    token: newUser.token,
  });
});

// Rota de autenticação de usuário
app.post('/signin', (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ mensagem: 'Parâmetros inválidos' });
  }

  const user = getUserByEmail(email);

  if (!user || !bcrypt.compareSync(senha, user.senha)) {
    return res.status(401).json({ mensagem: 'Usuário e/ou senha inválidos' });
  }

  user.ultimoLogin = new Date();
  user.token = generateToken(email);

  res.json({
    id: user.id,
    data_criacao: user.dataCriacao,
    data_atualizacao: user.dataAtualizacao,
    ultimo_login: user.ultimoLogin,
    token: user.token,
  });
});

// Rota de busca de usuário
app.get('/user', authenticateToken, (req, res) => {
  const userEmail = req.user.email;
  const user = getUserByEmail(userEmail);

  if (!user) {
    res.status(404).json({ mensagem: 'Usuário não encontrado' });
  } else {
    res.json({
      id: user.id,
      data_criacao: user.dataCriacao,
      data_atualizacao: user.dataAtualizacao,
      ultimo_login: user.ultimoLogin,
      token: user.token,
    });
  }
});

// Inicialização do servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
