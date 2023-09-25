# Cloud Book Platform Documentation

  

## Getting Started

  

### Pre-requisites

  

1. Ensure you have Python and pip installed.

2. It's recommended to use a virtual environment for isolated dependencies.

  

### Setup

  

1. Setup the virtual environment:

```bash

python  -m  venv  venv

```

  

2. Activate the virtual environment:

  

- On Windows:

```bash

.\venv\Scripts\activate

```

- On MacOS/Linux:

```bash

source venv/bin/activate

```

  

3. Install the required dependencies:

```bash

pip  install  -r  requirements.txt

```

  

4. Run migrations to set up the database:

```bash

python  manage.py  migrate

```

  

5. Start the development server:

```bash

python  manage.py  runserver

```

  

The server should now be running at `http://127.0.0.1:8000/`.

  

### Running Tests

  

To ensure that everything is set up correctly, run the tests:

  

```bash

python  manage.py  test

```

  

If everything is okay, you should see an "OK" at the end of the test output.

  

---

  

## API Documentation

  

### User Authentication

  

#### 1. Register a User

  

-  **Method:** POST

-  **URL:**  `/api/register/`

-  **Body:**

```json

{	
	"username": "john",
	"password": "password123"
}

```

  

#### 2. Login

  

-  **Method:** POST

-  **URL:**  `/api/login/`

-  **Body:**

```json

{
	"username": "john",
	"password": "password123"
}

```

> Note: After logging in, note down the token returned. This token is required for making authenticated requests.

  

### Sections

  

#### 3. Create a Section

  

-  **Method:** POST

-  **URL:**  `/api/section/`

-  **Headers:**  `Authorization: Token <YOUR_TOKEN_FROM_LOGIN>`

-  **Body:**

```json

{
	"book_id": 1,
	"title": "Introduction"
}

```

  

#### 4. Edit a Section

  

-  **Method:** PUT

-  **URL:**  `/api/section/<SECTION_ID>/`

-  **Headers:**  `Authorization: Token <YOUR_TOKEN_FROM_LOGIN>`

-  **Body:**

```json

{
	"new_title": "Updated Introduction"
}

```

  

### Collaborators

  

#### 5. Add Collaborator

  

-  **Method:** POST

-  **URL:**  `/api/manage-collaborator/`

-  **Headers:**  `Authorization: Token <YOUR_TOKEN_FROM_LOGIN>`

-  **Body:**

```json

{
	"book_id": 1,	
	"username": "jane"
}

```

  

#### 6. Remove Collaborator

  

-  **Method:** DELETE

-  **URL:**  `/api/manage-collaborator/`

-  **Headers:**  `Authorization: Token <YOUR_TOKEN_FROM_LOGIN>`

-  **Body:**

```json

{
	"book_id": 1,
	"username": "jane"
}

```



#### 7. Create Book

  

-  **Method:** POST

-  **URL:**  `/api/book/`

-  **Headers:**  `Authorization: Token <YOUR_TOKEN_FROM_LOGIN>`

-  **Body:**

```json

{
	"title": "My Book"
}

```

---

## Database Schema

### User Model (Django's built-in)
- **id**: Integer, Primary Key, Auto Increment
- **username**: String (Django Default)
- **password**: String (Django Default)

### Book Model
- **id**: Integer, Primary Key, Auto Increment
- **title**: Char (max 255 chars)
- **author_id**: ForeignKey to User

### Section Model
- **id**: Integer, Primary Key, Auto Increment
- **title**: Char (max 255 chars)
- **parent_id**: ForeignKey to Section (Nullable)
- **book_id**: ForeignKey to Book (Nullable)
---

## Overview of the Cloud Book Platform

### Introduction

The Cloud Book Platform is a Django-based web application designed to offer users the capability to create, manage, and collaborate on books and their individual sections. It emphasizes easy-to-use APIs and a database structure that optimizes information retrieval and manipulation. 

### Approach

1. **Project Initialization**: 
    - Started by setting up a Django environment, using a virtual environment to ensure isolation of dependencies.
    - The structure was defined based on the MVC (Model-View-Controller) architecture intrinsic to Django.

2. **User Management**: 
    - Utilized Django's built-in User model for authentication.
    - Created API endpoints for user registration and login. Authentication tokens were introduced to ensure secure and personalized access to resources.

3. **Database Design**:
    - Developed `Book` and `Section` models based on the requirements.
    - The `Book` model captures essential information about a book, including the title and its relationship with users (authors and collaborators).
    - The `Section` model allows hierarchical structuring by linking sections to their parent sections, ensuring scalability for books of varying lengths and complexities.

4. **API Development**:
    - Created RESTful APIs for primary operations like creating books, managing sections, and handling collaborators.
    - Used token-based authentication to secure the endpoints, ensuring that only registered and authenticated users can make specific changes.

5. **Collaboration Features**:
    - Incorporated functionality for users to add or remove collaborators to a book. 
    - A many-to-many relationship was established between the `Book` and `User` models to manage collaborations efficiently.

6. **Testing**:
    - Integrated a series of unit tests to ensure that all the primary functions of the platform work as expected.
    - Encouraged running these tests after setup to confirm a successful deployment.

### Implementation

- The application was built on the Django framework, capitalizing on its ORM capabilities, making database operations seamless and efficient.
  
- Used Django's built-in User authentication system to handle user registration, login, and session management, reducing the amount of custom coding required for these functions.

- The many-to-many relationship between books and collaborators was handled using Django's ORM capabilities, ensuring efficient querying and data integrity.

- Emphasized readability and maintainability in the codebase, making it easier for future developers to build upon or modify the existing structure.
---