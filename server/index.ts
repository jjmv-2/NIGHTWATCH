import cors from "cors"
import dotenv from "dotenv"
import express from "express"

import investigateRouter from "./routes/investigate"
import casesRouter from "./routes/cases"
dotenv.config()

const app = express()

const PORT =
  Number(process.env.PORT) || 3001

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
    ],
  }),
)

app.use(express.json())

app.get(
  "/api/health",
  (_req, res) => {
    res.json({
      status: "operational",
      service: "NIGHTWATCH API",
      timestamp:
        new Date().toISOString(),
    })
  },
)

app.use(
  "/api/investigate",
  investigateRouter,
)
app.use(
  "/api/cases",
  casesRouter,
)
app.listen(
  PORT,
  () => {
    console.log(
      `NIGHTWATCH API running on http://localhost:${PORT}`,
    )
  },
)