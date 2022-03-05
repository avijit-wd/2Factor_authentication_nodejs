require("dotenv").config();
import express, { Request, Response } from "express";
import cors from "cors";
import { routes } from "./routes";
import morgan from "morgan";
import { createConnection } from "typeorm";
import cookieParser from "cookie-parser";

createConnection().then((connection) => {
  if (connection) {
    console.log("DB connection established!");
  }
  const app = express();

  app.use(express.json());
  app.use(cookieParser());
  app.use(morgan("dev"));
  app.use(
    cors({
      credentials: true,
      origin: ["http://localhost:3000"],
    })
  );

  routes(app);

  app.listen(8000, () => console.log("Port running on port 8000"));
});
