import { pool } from '../database/connection.js';

const getUser = async (email) => {
  const query = 'SELECT * FROM usuarios WHERE email = $1;';
  const { rows } = await pool.query(query, [email]);
  return rows[0];
};

const createUser = async ({ email, password, rol, lenguage }) => {
  const query = 'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *;';
  const { rows } = await pool.query(query, [email, password, rol, lenguage]);
  return rows[0];
};

const verifyUserEmail = async (email) => {
  const query = 'SELECT email FROM usuarios WHERE email = $1;';
  const { rows } = await pool.query(query, [email]);
  return rows[0];
};

export const usersModel = {
  getUser,
  createUser,
  verifyUserEmail,
};
