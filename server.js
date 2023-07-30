import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';

const app = express();
app.use(
  cors({
    origin: ['http://localhost:5173'],
    methods: ['POST', 'GET', 'PUT', 'DELETE'],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

const con = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USERNAME || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_DBNAME || 'signup',
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: 'You are no Authenticated' });
  } else {
    jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
      // console.log(decoded.id);
      if (err) return res.json({ Error: 'Token wrong' });
      req.role = decoded.role;
      req.id = decoded.id;
      next();
    });
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/images');
  },
  filename: (req, file, cb) => {
    cb(
      null,
      file.fieldname + '_' + Date.now() + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
});

con.connect(function (err) {
  if (err) {
    console.log('Error in Connection');
  } else {
    console.log('Connected');
  }
});

app.get('/getEmployee', (req, res) => {
  const sql = 'SELECT * FROM employee';
  con.query(sql, (err, result) => {
    if (err) return res.json({ Error: 'Get employee error in sql' });
    return res.json({ Status: 'Success', Result: result });
  });
});

app.get('/getTasks', (req, res) => {
  const disableSafeModeQuery = 'SET SQL_SAFE_UPDATES = 0';
  const createTemporaryTableQuery = `
    CREATE TEMPORARY TABLE IF NOT EXISTS tmp_tasks AS
    SELECT tasks.id, employee.name AS assigned_to, employee.status AS new_status
    FROM tasks
    INNER JOIN employee ON employee.work = tasks.taskname`;
  const updateTasksQuery = `
    UPDATE tasks
    INNER JOIN tmp_tasks ON tasks.id = tmp_tasks.id
    SET tasks.assigned_to = tmp_tasks.assigned_to, tasks.status = tmp_tasks.new_status`;
  const dropTemporaryTableQuery = 'DROP TEMPORARY TABLE IF EXISTS tmp_tasks';
  const enableSafeModeQuery = 'SET SQL_SAFE_UPDATES = 1';

  con.query(disableSafeModeQuery, (err) => {
    if (err) {
      console.log('Error disabling safe mode:', err.message);
      return res.json({ Error: 'Error disabling safe mode' });
    }

    con.query(createTemporaryTableQuery, (err) => {
      if (err) {
        console.log('Error creating temporary table:', err.message);
        return res.json({ Error: 'Error creating temporary table' });
      }

      con.query(updateTasksQuery, (err) => {
        if (err) {
          console.log('Error updating tasks:', err.message);
          return res.json({ Error: 'Error updating tasks' });
        }

        con.query(dropTemporaryTableQuery, (err) => {
          if (err) {
            console.log('Error dropping temporary table:', err.message);
            return res.json({ Error: 'Error dropping temporary table' });
          }

          con.query(enableSafeModeQuery, (err) => {
            if (err) {
              console.log('Error enabling safe mode:', err.message);
              return res.json({ Error: 'Error enabling safe mode' });
            }

            const getTasksQuery = 'SELECT * FROM tasks ORDER BY status';
            con.query(getTasksQuery, (err, result) => {
              if (err) {
                console.log('Get Tasks error in SQL:', err.message);
                return res.json({ Error: 'Get Tasks error in SQL' });
              }

              return res.json({ Status: 'Success', Result: result });
            });
          });
        });
      });
    });
  });
});

app.get('/get/:id', verifyUser, (req, res) => {
  const id = req.params.id;
  const sql = 'SELECT * FROM employee where id = ?';
  con.query(sql, [id], (err, result) => {
    if (err) return res.json({ Error: 'Get employee error in sql' });
    return res.json({ Status: 'Success', Result: result });
  });
});

app.put('/update/:id', (req, res) => {
  const id = req.params.id;
  const sql =
    'UPDATE employee set work = ?, salary = ?, status =?, address = ?, name= ?, email=? WHERE id = ?';
  con.query(
    sql,
    [
      req.body.work,
      req.body.salary,
      req.body.status,
      req.body.address,
      req.body.name,
      req.body.email,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Error: 'update employee error in sql' });
      return res.json({ Status: 'Success' });
    }
  );
});
app.put('/updatestatus/:id', (req, res) => {
  const id = req.params.id;
  const sql = 'UPDATE employee set  status =? WHERE id = ?';
  con.query(sql, [req.body.status, id], (err, result) => {
    if (err) return res.json({ Error: 'update employee error in sql' });
    return res.json({ Status: 'Success' });
  });
});

app.delete('/delete/:id', (req, res) => {
  const id = req.params.id;
  const sql = 'Delete FROM employee WHERE id = ?';
  con.query(sql, [id], (err, result) => {
    if (err) return res.json({ Error: 'delete employee error in sql' });
    return res.json({ Status: 'Success' });
  });
});
app.delete('/deleteTask/:id', (req, res) => {
  const id = req.params.id;
  const sql = 'Delete FROM tasks WHERE id = ?';
  con.query(sql, [id], (err, result) => {
    if (err) return res.json({ Error: 'delete task error in sql' });
    return res.json({ Status: 'Success' });
  });
});

app.get('/dashboard', verifyUser, (req, res) => {
  return res.json({ Status: 'Success', role: req.role, id: req.id });
});

app.get('/adminCount', (req, res) => {
  const sql = 'Select count(id) as admin from users';
  con.query(sql, (err, result) => {
    if (err) return res.json({ Error: 'Error in runnig query' });
    return res.json(result);
  });
});
app.get('/employeeCount', (req, res) => {
  const sql = 'Select count(id) as employee from employee';
  con.query(sql, (err, result) => {
    if (err) return res.json({ Error: 'Error in runnig query' });
    return res.json(result);
  });
});

app.get('/salary', (req, res) => {
  const sql = 'Select sum(salary) as sumOfSalary from employee';
  con.query(sql, (err, result) => {
    if (err) return res.json({ Error: 'Error in runnig query' });
    return res.json(result);
  });
});

app.post('/login', (req, res) => {
  const sql = 'SELECT * FROM users Where email = ? AND  password = ?';
  con.query(sql, [req.body.email, req.body.password], (err, result) => {
    if (err)
      return res.json({ Status: 'Error', Error: 'Error in runnig query' });
    if (result.length > 0) {
      const id = result[0].id;
      const token = jwt.sign({ role: 'admin', id: id }, 'jwt-secret-key', {
        expiresIn: '1d',
      });
      res.cookie('token', token);
      return res.json({ Status: 'Success' });
    } else {
      return res.json({ Status: 'Error', Error: 'Wrong Email or Password' });
    }
  });
});

app.post('/employeelogin', (req, res) => {
  const sql = 'SELECT * FROM employee Where email = ?';
  con.query(sql, [req.body.email], (err, result) => {
    if (err)
      return res.json({ Status: 'Error', Error: 'Error in runnig query' });
    if (result.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        result[0].password,
        (err, response) => {
          if (err) return res.json({ Error: 'password error' });
          if (response) {
            const token = jwt.sign(
              { role: 'employee', id: result[0].id },
              'jwt-secret-key'
            );
            // console.log(token);
            res.cookie('token', token);
            return res.json({ Status: 'Success', id: result[0].id });
          } else {
            return res.json({
              Status: 'Error',
              Error: 'Wrong Email or Password',
            });
          }
        }
      );
    } else {
      return res.json({ Status: 'Error', Error: 'Wrong Email or Password' });
    }
  });
});

app.get('/employee/:id', (req, res) => {
  const id = req.params.id;
  // console.log(id);
  const sql = 'SELECT * FROM employee where id = ?';
  con.query(sql, [id], (err, result) => {
    if (err) return res.json({ Error: 'Get employee error in sql' });
    return res.json({ Status: 'Success', Result: result });
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ Status: 'Success' });
});
app.post('/createTask', (req, res) => {
  const sql = 'INSERT INTO `signup`.`tasks` (`taskname`) VALUES (?)';
  con.query(sql, [req.body.name], (err, result) => {
    if (err) return res.json({ Error: 'Inside createTask query' });
    return res.json({ Status: 'Success' });
  });
});

app.post('/create', upload.single('image'), (req, res) => {
  const sql =
    'INSERT INTO employee (`name`,`email`,`password`, `address`, `salary`,`image`, `work`, `status`) VALUES (?)';
  bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
    if (err) return res.json({ Error: 'Error in hashing password' });
    const values = [
      req.body.name,
      req.body.email,
      hash,
      req.body.address,
      req.body.salary,
      req.file.filename,
      'No Work',
      1,
    ];
    con.query(sql, [values], (err, result) => {
      if (err) return res.json({ Error: 'Inside singup query' });
      return res.json({ Status: 'Success' });
    });
  });
});

app.listen(8081, () => {
  console.log('Running');
});
