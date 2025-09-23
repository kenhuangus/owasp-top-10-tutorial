# OWASPedia: An Interactive Guide to Application Security

OWASPedia is a web application designed to be an interactive, educational resource for developers, security professionals, and students to learn about the most critical web application and Large Language Model (LLM) security risks, as defined by the Open Web Application Security Project (OWASP).

The application provides clear explanations, visual diagrams, and practical code examples to help users understand, identify, and mitigate these vulnerabilities.

## Features

- **OWASP Top 10 (2021):** Comprehensive coverage of the ten most critical web application security risks.
- **OWASP Top 10 for LLMs:** Detailed explanations for the new set of vulnerabilities specific to Large Language Model applications.
- **Detailed Vulnerability Pages:** Each vulnerability has a dedicated page that includes:
    - A concise summary and a detailed, bulleted explanation.
    - An attack vector diagram rendered with Mermaid.js to visualize the threat.
    - Side-by-side vulnerable and secure code examples in various languages.
    - Clear highlighting of the exact insecure/secure code snippets.
    - A summary of the potential impact of the vulnerability.
- **Best Practices AI:** An AI-powered tool built with Genkit that generates security best practices for any given threat type.
- **Modern, Responsive UI:** Built with ShadCN UI components and Tailwind CSS for a clean, accessible, and responsive user experience on all devices.
- **Interactive Sidebar:** A collapsible sidebar for easy navigation through the different vulnerability categories.

## Tech Stack

- **Framework:** [Next.js](https://nextjs.org/) (App Router)
- **Language:** [TypeScript](https://www.typescriptlang.org/)
- **UI:** [React](https://react.dev/)
- **Styling:** [Tailwind CSS](https://tailwindcss.com/)
- **Component Library:** [ShadCN UI](https://ui.shadcn.com/)
- **AI/Generative:** [Genkit](https://firebase.google.com/docs/genkit)
- **Diagrams:** [Mermaid.js](https://mermaid-js.github.io/mermaid/#/)
- **Icons:** [Lucide React](https://lucide.dev/)

## Getting Started

Follow these instructions to get a local copy of the project up and running.

### Prerequisites

- [Node.js](https://nodejs.org/en) (v20 or later)
- [npm](https://www.npmjs.com/) (or your preferred package manager)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <project-directory>
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Set up Environment Variables:**
    The AI features in this project rely on Genkit and the Google AI Gemini models.

    - Create a `.env` file in the root of your project by copying the `.env.example` file (if it exists) or creating a new one.
    - Obtain an API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
    - Add your API key to the `.env` file:
      ```
      GEMINI_API_KEY=your_google_ai_api_key
      ```

### Running the Development Server

Once the dependencies are installed and your environment variables are set, you can run the development server:

```bash
npm run dev
```

This will start the Next.js application, typically on `http://localhost:9002`. Open this URL in your browser to see the application.
