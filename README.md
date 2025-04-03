# Agentic AI Job Assistant

An intelligent AI-powered system that helps automate the job application process and prepare for interviews.

## Features

- **Job Scraper**: Automatically fetches job openings from multiple job sites
- **Resume Customizer**: Analyzes job descriptions and customizes your resume accordingly
- **Job Application Manager**: Handles the application process automatically
- **Interview Assistant**: AI-powered interview preparation and practice

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your API keys:
   ```
   OPENAI_API_KEY=your_openai_api_key
   LINKEDIN_EMAIL=your_linkedin_email
   LINKEDIN_PASSWORD=your_linkedin_password
   ```

## Project Structure

```
├── src/
│   ├── job_scraper/
│   │   ├── __init__.py
│   │   ├── linkedin_scraper.py
│   │   └── indeed_scraper.py
│   ├── resume_customizer/
│   │   ├── __init__.py
│   │   ├── resume_parser.py
│   │   └── resume_generator.py
│   ├── application_manager/
│   │   ├── __init__.py
│   │   └── application_handler.py
│   └── interview_assistant/
│       ├── __init__.py
│       └── interview_bot.py
├── requirements.txt
└── README.md
```

## Usage

1. Configure your job search preferences in `config.py`
2. Run the job scraper:
   ```bash
   python src/main.py --mode scrape
   ```
3. Customize resume for specific jobs:
   ```bash
   python src/main.py --mode customize-resume
   ```
4. Start interview practice:
   ```bash
   python src/main.py --mode interview
   ```

## License

MIT License 