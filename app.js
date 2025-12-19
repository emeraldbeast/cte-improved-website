const express = require('express');
const path = require('path');
const app = express();

app.use(express.static(path.join(process.cwd(), 'public')));

app.set('views', path.join(process.cwd(), 'views'));
app.set('view engine', 'ejs');

app.get('/', (req, res) => {
  res.render('index');
});

module.exports = app;
