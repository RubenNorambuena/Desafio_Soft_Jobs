import "dotenv/config";
import pkg from "pg";
const { Pool } = pkg;

// Cambia los datos de acuerdo a tu configuracion de postgres
export const pool = new Pool({
  host: 'localhost',
  user: 'postgres',
  password: 'Rn123456',
  database: 'softjobs',
  port: 5432,
  allowExitOnIdle: true,
});