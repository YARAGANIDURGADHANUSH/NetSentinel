# Use an official Node runtime as a parent image
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of your frontend application source code
COPY . .

# Expose port 3000 for the React development server
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
