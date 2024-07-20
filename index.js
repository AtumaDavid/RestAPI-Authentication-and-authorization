const express = require("express");
const routes = require("./routes/route");

const app = express();
const PORT = process.env.port || 5000;

app.use(express.json());

app.use(routes);

app.listen(PORT, () => console.log(`Listening on: ${PORT}`));
