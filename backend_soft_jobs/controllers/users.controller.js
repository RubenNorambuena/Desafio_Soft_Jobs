import { usersModel } from '../models/users.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config();

const registerUser = async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    if (!email || !password || !rol || !lenguage) {
      throw { message: 'Email, password, role and language are required.' };
    }

    const verifyEmail = await usersModel.verifyUserEmail(email);
    if (verifyEmail) {
      throw { message: 'Email no available.' };
    }

    const result = await usersModel.createUser({
      email,
      password: bcrypt.hashSync(password, 10),
      rol,
      lenguage,
    });

    console.log('User Register: ', result);

    res.status(201).json({ message: 'User created successfully.' });

  } catch (error) {
    console.log('Error Register: ', error.message);
    res.status(500).json({ message: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { email } = req.body;
    const token = jwt.sign({ email }, process.env.JWT_PASSWORD);

    console.log('Token Login: ', token);
    
    res.json({ token });
    
  } catch (error) {
    console.log('Error Login: ', error.message);
    res.status(500).json({ message: error.message });
  }
};

const getUser = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await usersModel.getUser(email);

    console.log('Get User: ', user);

    res.json([user]);

  } catch (error) {
    console.log('Error get User: ', error.message);
    res.status(500).json({ message: error.message });
  }
};

export const usersController = {
  registerUser,
  login,
  getUser,
};
