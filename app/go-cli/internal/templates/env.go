package templates

import "strings"

// EnvExample returns a commented .env.example for the given preset.
func EnvExample(preset string) string {
	var b strings.Builder
	b.WriteString("# Schema only. Production values live on the VPS at secrets.host.env_file.\n")
	b.WriteString("# Do not copy this to a workstation .env for deploy.\n\n")

	switch preset {
	case "laravel":
		b.WriteString("APP_NAME=MyApp\n")
		b.WriteString("APP_ENV=production\n")
		b.WriteString("APP_KEY=\n")
		b.WriteString("APP_DEBUG=false\n")
		b.WriteString("APP_URL=https://example.com\n\n")
		b.WriteString("# Database\n")
		b.WriteString("DB_CONNECTION=pgsql\n")
		b.WriteString("DB_HOST=127.0.0.1\n")
		b.WriteString("DB_PORT=5432\n")
		b.WriteString("DB_DATABASE=app\n")
		b.WriteString("DB_USERNAME=app\n")
		b.WriteString("DB_PASSWORD=\n\n")
		b.WriteString("# Cache & Queue\n")
		b.WriteString("CACHE_STORE=file\n")
		b.WriteString("QUEUE_CONNECTION=sync\n\n")
		b.WriteString("# Mail\n")
		b.WriteString("MAIL_MAILER=smtp\n")
		b.WriteString("MAIL_HOST=127.0.0.1\n")
		b.WriteString("MAIL_PORT=1025\n")
		b.WriteString("MAIL_USERNAME=null\n")
		b.WriteString("MAIL_PASSWORD=null\n")

	case "symfony":
		b.WriteString("APP_ENV=prod\n")
		b.WriteString("APP_SECRET=\n\n")
		b.WriteString("# Database (Doctrine)\n")
		b.WriteString("DATABASE_URL=\"postgresql://app:password@127.0.0.1:5432/app?serverVersion=16&charset=utf8\"\n\n")
		b.WriteString("# Messenger\n")
		b.WriteString("MESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0\n\n")
		b.WriteString("# Mailer\n")
		b.WriteString("MAILER_DSN=smtp://127.0.0.1:1025\n")

	case "nextjs":
		b.WriteString("NODE_ENV=production\n")
		b.WriteString("NEXT_PUBLIC_API_URL=https://api.example.com\n\n")
		b.WriteString("# Database (if applicable)\n")
		b.WriteString("DATABASE_URL=\n")

	case "node-api", "hono", "fastify", "tanstack-start":
		b.WriteString("NODE_ENV=production\n")
		b.WriteString("PORT=3000\n\n")
		b.WriteString("# Database (if applicable)\n")
		b.WriteString("DATABASE_URL=\n")

	case "fastapi":
		b.WriteString("ENVIRONMENT=production\n")
		b.WriteString("PORT=8000\n\n")
		b.WriteString("# Database (if applicable)\n")
		b.WriteString("DATABASE_URL=\n")

	default:
		b.WriteString("# Add your environment variables here\n")
	}

	return b.String()
}
