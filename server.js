import express from "express";
import mysql from "mysql";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import multer from "multer";
import path from "path";
import fs from 'fs';
import { fileURLToPath } from "url";
import nodemailer from "nodemailer"

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// Verificar si el directorio 'uploads' existe y crearlo si no es así
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir); // Crea el directorio 'uploads' si no existe
}

// Configuración de almacenamiento para multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // Asegúrate de que esta carpeta existe
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Nombre único para evitar sobrescribir archivos
  }
});

const upload = multer({ storage });

const transporter = nodemailer.createTransport({
    service: 'GMAIL',
    auth: {
        user: 'jloppad@g.educaand.es',
        pass: 'nexi xlub dvbu ugau'
    }
});

// Configuración para aumentar el límite del tamaño de payload
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const db = mysql.createConnection({
  host: "bpihkooxjbi7qzjwiunv-mysql.services.clever-cloud.com",
  user: "ux4igz7oaxfpomud",
  password: "XwWg3jyvYcWXDNbgIN8h",
  database: "bpihkooxjbi7qzjwiunv",
  port: 3306
});

// const db = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "practica",
//   database: "library",
// });


app.get("/", (req, res) => {
  res.json("Library database");
});

//////////////////////////////////////////////////////////////////////////
/////////////////////           Rutas CRUD          //////////////////////
//////////////////////////////////////////////////////////////////////////


/////////////           Rutas para Books          /////////////    

// Obtener todos los libros
app.get("/books", (req, res) => {
  let query = "SELECT * FROM books"; 

  db.query(query, (err, data) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Error fetching books" });
    }

    res.json({
      books: data
    });
  });
});

// Obtener un libro específico por ID
app.get("/books/:id", (req, res) => {
  const bookId = req.params.id;
  const query = "SELECT * FROM books WHERE id = ?";

  db.query(query, [bookId], (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error fetching book" });
    }

    if (data.length === 0) {
      return res.status(404).json({ error: "Book not found" });
    }

    res.json(data[0]);
  });
});

// Actualizar un libro
app.put("/books/:id", (req, res) => {
  const bookId = req.params.id;
  const {
    title,
    author,
    cover,
    intro,
    review,
    completed,
    userId,
    averageRating
  } = req.body;

  const query = `
    UPDATE books SET title = ?, author = ?, cover = ?, intro = ?, review = ?, 
    completed = ?, userId = ?, averageRating = ? WHERE id = ?
  `;

  db.query(
    query,
    [title, author, cover, intro, review, completed, userId, averageRating, bookId],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error updating book" });
      }

      res.json({ message: "Book updated successfully" });
    }
  );
});

// Crear un nuevo libro
app.post("/books", (req, res) => {
  const {
    title,
    author,
    cover,
    intro,
    review,
    completed = null,  
    userId,
    averageRating
  } = req.body;

  const query = `
    INSERT INTO books (title, author, cover, intro, review, completed, userId, averageRating)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [title, author, cover, intro, review, completed, userId, averageRating],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error creating book" });
      }

      res.json({ message: "Book created successfully", id: result.insertId });
    }
  );
});

// Eliminar un libro
app.delete("/books/:id", (req, res) => {
  const bookId = req.params.id;

  const query = `DELETE FROM books WHERE id = ?`;

  db.query(query, [bookId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error deleting book" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Book not found" });
    }

    res.json({ message: "Book deleted successfully" });
  });
});

/////////////           Rutas para Users          /////////////    

// Obtener todos los usuarios
app.get("/users", (req, res) => {
  let query = "SELECT * FROM users"; 

  db.query(query, (err, data) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Error fetching users" });
    }

    res.json({
      users: data
    });
  });
});

// Obtener un usuario específico por ID
app.get("/users/:id", (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = ?";

  db.query(query, [userId], (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error fetching user" });
    }

    if (data.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(data[0]);
  });
});

// Actualizar un usuario
app.put("/users/:id", (req, res) => {
  const userId = req.params.id;
  const { username, password, email, authentication, admin } = req.body;

  const query = `
    UPDATE users SET username = ?, password = ?, email = ?, authentication = ?, admin = ? WHERE id = ?
  `;

  db.query(
    query,
    [username, password, email, authentication, admin, userId],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error updating user" });
      }

      res.json({ message: "User updated successfully" });
    }
  );
});

// Crear un nuevo usuario
app.post("/users", (req, res) => {
  const { username, password, email, authentication = 0, admin = 0 } = req.body;

  const query = `
    INSERT INTO users (username, password, email, authentication, admin)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [username, password, email, authentication, admin],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error creating user" });
      }

      res.json({ message: "User created successfully", id: result.insertId });
    }
  );
});

// Eliminar un usuario
app.delete("/users/:id", (req, res) => {
  const userId = req.params.id;

  const query = `DELETE FROM users WHERE id = ?`;

  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error deleting user" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  });
});

/////////////           Rutas para Comments          /////////////    

// Obtener todas las imágenes
app.get("/comments", (req, res) => {
  const query = "SELECT * FROM comments";

  db.query(query, (err, data) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Error fetching comments" });
    }

    res.json({
      comments: data
    });
  });
});

// Obtener un comentario específica por ID
app.get("/comments/:id", (req, res) => {
  const commentId = req.params.id;
  const query = "SELECT * FROM comments WHERE id = ?";

  db.query(query, [commentId], (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error fetching comment" });
    }

    if (data.length === 0) {
      return res.status(404).json({ error: "Comment not found" });
    }

    res.json(data[0]);
  });
});

// Crear un nuevo comentario
app.post("/comments", (req, res) => {
  const { userId, bookId, comment } = req.body;

  const query = `
    INSERT INTO comments (userId, bookId, comment)
    VALUES (?, ?, ?)
  `;

  db.query(
    query,
    [userId, bookId, comment],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error creating comment" });
      }

      res.json({ message: "Comment created successfully", id: result.insertId });
    }
  );
});

// Actualizar un comentario
app.put("/comments/:id", (req, res) => {
  const commentId = req.params.id;
  const { comment } = req.body;

  const query = `
    UPDATE comments SET comment = ? WHERE id = ?
  `;

  db.query(
    query,
    [comment, commentId],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error updating comment" });
      }

      res.json({ message: "Comment updated successfully" });
    }
  );
});

// Eliminar un comentario
app.delete("/comments/:id", (req, res) => {
  const commentId = req.params.id;

  const query = `DELETE FROM comments WHERE id = ?`;

  db.query(query, [commentId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error deleting comment" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Comment not found" });
    }

    res.json({ message: "Comment deleted successfully" });
  });
});

/////////////           Rutas para Ratings          /////////////    

// Obtener todas las valoraciones
app.get("/ratings", (req, res) => {
  const query = "SELECT * FROM ratings";

  db.query(query, (err, data) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Error fetching ratings" });
    }

    res.json({
      ratings: data
    });
  });
});

// Obtener una valoración específica por ID
app.get("/ratings/:id", (req, res) => {
  const ratingId = req.params.id;
  const query = "SELECT * FROM ratings WHERE id = ?";

  db.query(query, [ratingId], (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error fetching rating" });
    }

    if (data.length === 0) {
      return res.status(404).json({ error: "Rating not found" });
    }

    res.json(data[0]);
  });
});

// Crear una nueva valoración
app.post("/ratings", (req, res) => {
  const { userId, bookId, value } = req.body;

  const checkQuery = `
    SELECT * FROM ratings WHERE userId = ? AND bookId = ?
  `;

  // Primero, verifica si el usuario ya ha calificado este libro
  db.query(checkQuery, [userId, bookId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error checking rating" });
    }

    if (result.length > 0) {
      // Si ya existe una valoración, actualiza el valor
      const updateQuery = `
        UPDATE ratings SET value = ? WHERE userId = ? AND bookId = ?
      `;
      
      db.query(updateQuery, [value, userId, bookId], (updateErr) => {
        if (updateErr) {
          console.error(updateErr);
          return res.status(500).json({ error: "Error updating rating" });
        }
        updateAverageRating(bookId); 
        res.json({ message: "Rating updated successfully" });
      });
    } else {
      // Si no existe, inserta una nueva valoración
      const insertQuery = `
        INSERT INTO ratings (userId, bookId, value)
        VALUES (?, ?, ?)
      `;
      
      db.query(insertQuery, [userId, bookId, value], (insertErr, insertResult) => {
        if (insertErr) {
          console.error(insertErr);
          return res.status(500).json({ error: "Error creating rating" });
        }
        updateAverageRating(bookId); 
        res.json({ message: "Rating created successfully", id: insertResult.insertId });
      });
    }
  });
});

// Actualizar una valoración
app.put("/ratings/:id", (req, res) => {
  const ratingId = req.params.id;
  const { value } = req.body;

  if (value < 1 || value > 5) {
    return res.status(400).json({ error: "Rating value must be between 1 and 5" });
  }

  const query = `
    UPDATE ratings SET value = ? WHERE id = ?
  `;

  db.query(
    query,
    [value, ratingId],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error updating rating" });
      }
      updateAverageRating(bookId); 
      res.json({ message: "Rating updated successfully" });
    }
  );
});

// Eliminar una valoración
app.delete("/ratings/:id", (req, res) => {
  const ratingId = req.params.id;

  // Primero obtenemos el bookId asociado a esta valoración
  const getBookIdQuery = `SELECT bookId FROM ratings WHERE id = ?`;

  db.query(getBookIdQuery, [ratingId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error retrieving rating" });
    }

    if (result.length === 0) {
      return res.status(404).json({ error: "Rating not found" });
    }

    const bookId = result[0].bookId;

    // Ahora eliminamos la valoración
    const deleteQuery = `DELETE FROM ratings WHERE id = ?`;

    db.query(deleteQuery, [ratingId], (deleteErr, deleteResult) => {
      if (deleteErr) {
        console.error(deleteErr);
        return res.status(500).json({ error: "Error deleting rating" });
      }

      if (deleteResult.affectedRows === 0) {
        return res.status(404).json({ error: "Rating not found" });
      }

      // Finalmente, actualizamos la media
      updateAverageRating(bookId);

      res.json({ message: "Rating deleted successfully" });
    });
  });
});


/////////////           Rutas para Book Images          /////////////    

// Obtener todas las imágenes
app.get("/book_images", (req, res) => {
  const query = "SELECT * FROM book_images";

  db.query(query, (err, data) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Error fetching book images" });
    }

    res.json({
      book_images: data
    });
  });
});

// Obtener una imagen específica por ID
app.get("/book_images/:id", (req, res) => {
  const imageId = req.params.id;
  const query = "SELECT * FROM book_images WHERE id = ?";

  db.query(query, [imageId], (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error fetching book image" });
    }

    if (data.length === 0) {
      return res.status(404).json({ error: "Book image not found" });
    }

    res.json(data[0]);
  });
});

// Crear una nueva imagen
app.post("/book_images", (req, res) => {
  const { bookId, image_url } = req.body;

  const query = `
    INSERT INTO book_images (book_id, image_url)
    VALUES (?, ?)
  `;

  db.query(query, [bookId, image_url], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error creating book image" });
    }

    res.json({ message: "Book image created successfully", id: result.insertId });
  });
});

// Actualizar una imagen
app.put("/book_images/:id", (req, res) => {
  const imageId = req.params.id;
  const { image_url } = req.body;

  const query = `
    UPDATE book_images SET image_url = ? WHERE id = ?
  `;

  db.query(query, [image_url, imageId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error updating book image" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Book image not found" });
    }

    res.json({ message: "Book image updated successfully" });
  });
});

// Eliminar una imagen
app.delete("/book_images/:id", (req, res) => {
  const imageId = req.params.id;

  const query = `
    DELETE FROM book_images WHERE id = ?
  `;

  db.query(query, [imageId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error deleting book image" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Book image not found" });
    }

    res.json({ message: "Book image deleted successfully" });
  });
});

//////////////////////////////////////////////////////////////////////////
/////////////////           Rutas Personalizadas          ////////////////
//////////////////////////////////////////////////////////////////////////


/////////////           Rutas para Control de Sesion          /////////////    

// Ruta para registro de usuario
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;

  // Comprobar si el username ya existe en la base de datos
  const checkUsernameQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
  db.query(checkUsernameQuery, [username, email], (err, results) => {
    if (results.length > 0) {
      // Si ya existe el username o email
      return res.status(400).json({ error: 'The username or email is already in use' });
    }

    // Si el username no existe, continuar con el registro
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ error: 'Error generating password' });
      }

      const q = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
      db.query(q, [username, hashedPassword, email], (err, data) => {
        if (err) {
          return res.status(500).json({ error: 'Error registering user' });
        }

        // Obtener el id del usuario insertado
        const userId = data.insertId;

        // Generar token JWT para la verificación del correo
        const token = jwt.sign({ id: userId, email }, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', { expiresIn: '24h' });

        // Crear el enlace de verificación
        const verificationUrl = `https://api-wabm.onrender.com/verifymail/${email}`;

        const mailOptions = {
          from: 'jloppad@g.educaand.es',
          to: email,
          subject: 'Account Verification Library Review',
          html: `
            <html>
              <body>
                <h1>Welcome to Library Review</h1>
                <p>Click the link below to verify your email and activate your account.</p>
                <a href="${verificationUrl}">Verify Email</a>
              </body>
            </html>`
        };

        // Enviar el correo de verificación
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error(error);
            return res.status(500).send("Error sending verification email");
          } else {
            console.log('Verification email sent: ' + info.response);
            return res.status(200).json({
              message: 'User registered successfully. A verification email has been sent.',
              token,
              userId,
              username
            });
          }
        });
      });
    });
  });
});

// Ruta para iniciar sesión
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const q = 'SELECT * FROM users WHERE username = ?';
  db.query(q, [username], (err, data) => {
    if (err || data.length === 0) {
      return res.status(400).json({ error: 'Wrong credentials' });
    }

    const user = data[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(400).json({ error: 'Wrong credentials' });
      }

      if (user.authentication == 0) {
        return res.status(400).json({ error: 'Not validated user' });
      }

      // Generar token JWT
      const token = jwt.sign({ id: user.id }, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', { expiresIn: '1h' });

      // Enviar la respuesta con token, userId y username
      return res.json({ message: 'Successful login', token, userId: user.id, username: user.username });
    });
  });
});

/////////////           Rutas para Usuario          /////////////  

// Ruta para verificar el correo electrónico del usuario
app.get("/verifymail/:email", (req, res) => {
  const { email } = req.params;

  const queryVerificarCorreo = "UPDATE users SET authentication = 1 WHERE email = ?";

  db.query(queryVerificarCorreo, [email], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error verifying email' });
    }

    if (result.affectedRows > 0) {
      return res.redirect("https://libraryreviews.vercel.app/login?verified=true");
    } else {
      return res.status(400).json({ error: 'User not found or already verified' });
    }
  });

});

/////////////           Rutas para Libro          /////////////  

// Ruta GET para obtener todos los libros con paginación y búsqueda
app.get("/libros", (req, res) => {
  const { search, page = 1, limit = 5 } = req.query;
  const offset = (page - 1) * limit;

  let query = "SELECT * FROM books";
  let queryParams = [];

  // Si hay un término de búsqueda, agregar filtro por título
  if (search) {
    query += " WHERE title LIKE ?";
    queryParams.push(`%${search}%`);
  }

  query += " ORDER BY averageRating DESC LIMIT ? OFFSET ?";
  queryParams.push(parseInt(limit), parseInt(offset));

  db.query(query, queryParams, (err, data) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Error fetching books" });
    }

    // Consulta para contar los libros totales (teniendo en cuenta el filtro si lo hay)
    let countQuery = "SELECT COUNT(*) AS total FROM books";
    let countParams = [];

    if (search) {
      countQuery += " WHERE title LIKE ?";
      countParams.push(`%${search}%`);
    }

    db.query(countQuery, countParams, (err, countData) => {
      if (err) {
        return res.status(500).json({ error: "Error fetching total count" });
      }
      res.json({
        books: data,
        total: countData[0].total
      });
    });
  });
});

// Ruta GET para obtener libros por el userId
app.get("/libros/usuario/:userid", (req, res) => {
  const { userid } = req.params;
  const { search, page = 1, limit = 5 } = req.query;
  const offset = (page - 1) * limit;

  let query = "SELECT * FROM books WHERE userId = ?";
  let queryParams = [userid];

  if (search) {
    query += " AND title LIKE ?";
    queryParams.push(`%${search}%`);
  }

  query += " ORDER BY averageRating DESC LIMIT ? OFFSET ?";
  queryParams.push(parseInt(limit), parseInt(offset));

  db.query(query, queryParams, (err, data) => {
    if (err) return res.status(500).json({ error: "Error fetching books" });

    let countQuery = "SELECT COUNT(*) AS total FROM books WHERE userId = ?";
    let countParams = [userid];

    if (search) {
      countQuery += " AND title LIKE ?";
      countParams.push(`%${search}%`);
    }

    db.query(countQuery, countParams, (err, countData) => {
      if (err) return res.status(500).json({ error: "Error fetching count" });

      res.json({
        books: data,
        total: countData[0].total
      });
    });
  });
});


// Ruta POST para añadir un nuevo libro
app.post("/libros", upload.single('cover'), (req, res) => {

  const { title, author, intro, completed, review, userId } = req.body;
  const coverPath = req.file ? `/uploads/${req.file.filename}` : null;

  if (!title || !author || !userId) {
    return res.status(400).json({ error: 'Mandatory data missing' });
  }

  const insertQuery = 'INSERT INTO books (title, author, cover, intro, completed, review, userId) VALUES (?, ?, ?, ?, ?, ?, ?)';
  db.query(insertQuery, [title, author, coverPath, intro, completed, review, userId], (err, data) => {
    if (err) {
      console.error('Error en la consulta SQL:', err);
      return res.status(500).json({ error: 'Error registering the book', details: err });
    }

    // Devolver el ID del libro recién creado
    return res.status(201).json({ message: 'Book successfully registered', coverPath, bookId: data.insertId });
  });
});

// Ruta PUT para actualizar un libro por su ID
app.put("/libros/:id", upload.single("cover"), (req, res) => {
  const bookId = req.params.id;
  const { title, author, intro, completed, review } = req.body;
  const coverPath = req.file ? `/uploads/${req.file.filename}` : null;

  let query = "UPDATE books SET title = ?, author = ?, intro = ?, completed = ?, review = ?";
  let values = [title, author, intro, completed, review];

  // Si se sube una nueva portada, actualizar el campo cover
  if (coverPath) {
    query += ", cover = ?";
    values.push(coverPath);
  }

  query += " WHERE id = ?";
  values.push(bookId);

  db.query(query, values, (err, data) => {
    if (err) {
      return res.status(500).json({ error: "Error updating book" });
    }

    if (data.affectedRows === 0) {
      return res.status(404).json({ error: "Book not found" });
    }

    return res.json({ message: "Correctly updated book" });
  });
});

/////////////           Rutas para Comentarios          /////////////  

// Ruta para obtener comentarios de un libro con username y soporte para paginación
app.get("/comentarios/:bookId", (req, res) => {
  const { bookId } = req.params;
  const { page = 1, limit = 5 } = req.query; 

  const offset = (page - 1) * limit;

  const query = `
      SELECT comments.*, users.username 
      FROM comments 
      JOIN users ON comments.userId = users.id 
      WHERE comments.bookId = ?
      ORDER BY comments.createdAt DESC
      LIMIT ? OFFSET ?
  `;

  db.query(query, [bookId, parseInt(limit), parseInt(offset)], (err, data) => {
      if (err) return res.status(500).json({ error: "Error fetching comments" });
      
      // Query to count total comments for pagination
      const countQuery = `SELECT COUNT(*) AS total FROM comments WHERE bookId = ?`;
      
      db.query(countQuery, [bookId], (err, countData) => {
          if (err) return res.status(500).json({ error: "Error fetching total count" });
          
          // Return comments and total count
          res.json({
              comments: data,
              total: countData[0].total
          });
      });
  });
});

/////////////           Rutas para Valoracion          /////////////  

// Ruta GET par aobtener la valoracion de un libro de un usuario
app.get("/valoracion/:userid/:bookid", (req, res) => {
  const { userid, bookid } = req.params;
  const q = "SELECT * FROM ratings WHERE userId = ? AND bookId = ?";

  db.query(q, [userid, bookid], (err, data) => {
      if (err) {
          console.log(err);
          return res.status(500).json({ error: "Server error" });
      }
      if (data.length > 0) {
          return res.json(data);
      }
      return res.json(0);
  });
});

/////////////           Rutas para Imagenes          /////////////  

// Ruta GET para obtener las url de las images por id de libro
app.get("/libros/:id/imagenes", (req, res) => {
  const { id } = req.params;
  const q = "SELECT image_url FROM book_images WHERE book_id = ?";

  db.query(q, [id], (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error retrieving images" });
    }
    return res.json(data.map(row => row.image_url)); // Devuelve solo un array con URLs
  });  
});

// Ruta POST para añadir un nuevas imagenes
app.post("/libros/:bookId/imagen", upload.single('image'), (req, res) => {

  const bookId = req.params.bookId;
  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

  const insertImageQuery = 'INSERT INTO book_images (book_id, image_url) VALUES (?, ?)';

 db.query(insertImageQuery, [bookId, imagePath], (err, data) => {
          if (err) {
              return res.status(500).json({ error: 'Error uploading images', details: err });
          }
            return res.status(201).json({ message: 'Images uploaded successfully' });
      });
});

// Ruta PUT para actualizar las imágenes
app.put("/libros/:bookId/imagen", upload.single('image'), (req, res) => {
  const bookId = req.params.bookId;
  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

  if (!imagePath) {
      return res.status(400).json({ error: 'No image file uploaded' });
  }

  const insertImageQuery = 'INSERT INTO book_images (book_id, image_url) VALUES (?, ?)';

  db.query(insertImageQuery, [bookId, imagePath], (err, data) => {
      if (err) {
          return res.status(500).json({ error: 'Error inserting image', details: err });
      }
      return res.status(200).json({ message: 'Image added successfully' });
  });
});

// Ruta DELETE para eliminar las imagenes de un libro
app.delete("/libros/:bookId/imagenes", (req, res) => {
  const bookId = req.params.bookId;

  const deleteImagesQuery = 'DELETE FROM book_images WHERE book_id = ?';

  db.query(deleteImagesQuery, [bookId], (err, result) => {
      if (err) {
          return res.status(500).json({ error: 'Error deleting images', details: err });
      }
      return res.status(200).json({ message: 'Images deleted successfully' });
  });
});

function updateAverageRating(bookId) {
  const query = `
    SELECT AVG(value) AS avgRating FROM ratings WHERE bookId = ?
  `;

  db.query(query, [bookId], (err, result) => {
    if (err) {
      return console.error("Error calculating average rating:", err);
    }

    const averageRating = result[0].avgRating || 0;

    const updateQuery = `
      UPDATE books SET averageRating = ? WHERE id = ?
    `;

    db.query(updateQuery, [averageRating, bookId], (updateErr) => {
      if (updateErr) {
        console.error("Error updating average rating:", updateErr);
      }
    });
  });
}

app.listen(8800, '0.0.0.0', () => {
  console.log("Connected to backend.");
});