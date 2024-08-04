import { usersModel } from '../models/users.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config();

export const verifyCredentials = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      throw { message: 'Email and password requerida.' };
    }

    const user = await usersModel.getUser(email);
    if (!user) {
      throw { message: `Este email no esta registrado${email}.` };
    }

    const verifyPassword = await bcrypt.compare(password, user.password);
    if (!verifyPassword) {
      throw { message: 'Password incorrecta.' };
    }

    next();
    
  } catch (error) {
    console.log('Login error: ', error.message);
    res.status(500).json({ message: error.message });
  }
};

export const verifyToken = (req, res, next) => {
  try {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
      throw { message: 'Token no proporcionado.' };
    }

    const token = authorizationHeader.split(' ')[1];
    if (!token) {
      throw { message: 'Formato de token invalido.' };
    }

    const payload = jwt.verify(token, process.env.JWT_PASSWORD);
    if (!payload) {
      throw { message: 'Token invalido.' };
    }

    req.body.email = payload.email;

    next();
  } catch (error) {
    console.log('Error verifyToken: ', error.message);
    res.status(401).json({ message: error.message });
  }
};
