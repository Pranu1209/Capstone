# Effort Estimation Tool

## Introduction
The Effort Estimation Tool is a web application designed to provide users with accurate estimates for various tasks based on historical data stored in a MongoDB database. This tool allows users to register, submit details of the estimation required, and utilizes a formula to aggregate historical data and predict new estimates.

## Table of Contents
1. [Project Overview](#project-overview)
2. [User Stories](#user-stories)
3. [Project Components](#project-components)
4. [Technical Steps of Implementation](#technical-steps-of-implementation)
5. [Estimation Tool Project Submission Criteria](#estimation-tool-project-submission-criteria)

## Project Overview
The Effort Estimation Tool aims to streamline the estimation process by providing users with accurate estimates for tasks based on historical data. The tool consists of a user-friendly interface for submission and retrieval of estimations, a backend system for calculation and database interaction, and a MongoDB database for storing historical estimation data.

## User Stories
The following user stories guide the development of the Effort Estimation Tool:
1. **User Registration and Authentication**: Users can register for an account securely and log in to access the tool.
2. **Estimation Submission**: Users can input task details, specify parameters, and submit requests for estimation.
3. **Estimation Calculation**: The system calculates estimates based on historical data and displays them clearly with a confidence level/range.
4. **Database Interaction**: The tool fetches historical data from the MongoDB database and updates it with new estimations.
5. **UI/UX Design**: The interface is intuitive, responsive, and provides feedback on user actions and errors.
6. **Testing**: Comprehensive unit and integration tests ensure the functionality and responsiveness of the application.

## Project Components
1. **Front-End**: HTML, CSS, and JavaScript (ES6/TypeScript) for the user interface, AJAX for asynchronous communication, and Jinja2 for server-side templating.
2. **Back-End**: Python with Flask framework for the backend, user authentication, and MongoDB database interaction.
3. **Database Management**: MongoDB database schema design, CRUD operations, and data integrity/security measures.
4. **Deployment**: Docker for containerization, CI/CD pipelines for automated testing and deployment.
5. **Testing**: Unit tests for backend and frontend components, integration tests, and usability testing.

## Technical Steps of Implementation
The implementation of the Effort Estimation Tool involves the following technical steps:
1. **User Registration and Authentication**: Implement registration form, Flask-User/Flask-Security integration, secure storage of user credentials, and JWT for authentication token generation/validation.
2. **Estimation Submission**: Design submission form, utilize AJAX for data submission, implement RESTful API endpoints, validate and store estimation details in MongoDB.
3. **Estimation Calculation**: Retrieve historical data from MongoDB, analyze data for patterns, develop estimation algorithm, and display calculated estimates with confidence level/range.
4. **Database Interaction**: Connect to MongoDB using Flask-PyMongo, define database models/schema, implement CRUD operations, and update historical data with new estimations.
5. **UI/UX Design**: Design responsive UI components, enhance frontend with JavaScript, implement client-side form validation, and utilize AJAX for smooth data retrieval.
6. **Testing**: Write unit tests for backend APIs using pytest, mock database interactions, implement integration tests, and conduct usability testing.

## Estimation Tool Project Submission Criteria
To ensure the originality and quality of the project submission, adhere to the following guidelines:
- Submission Components: Presentation deck, solution code, screenshots of output, and README file.
- Code Originality: Original work with proper citation of external sources.
- Presentation and Documentation: Clear presentation deck and informative README file.
- Functionality and Completeness: Implement all required features with error handling and smooth user experience.
- Evaluation Criteria: Originality, functionality, code quality, presentation/documentation.

## How to Run the Application
1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Install dependencies using `pip install -r requirements.txt`.
4. Set up MongoDB database and configure connection settings in `config.py`.
5. Run the Flask application using `python app.py`.
6. Access the application in your web browser at `http://localhost:5000`.

For detailed instructions and additional notes, refer to the README file included in the project submission.

---
© 2024 Effort Estimation Tool. All rights reserved.
