import type { Metadata } from "next";
import "./globals.css";
import "highlight.js/styles/github-dark.css";

export const metadata: Metadata = {
	title: "go-secretbox",
	description:
		"Password-based encryption for data at rest in Go. Argon2id + AES-256-GCM, sentinel-verified vaults, self-describing one-shot blobs, and safe key rotation.",
};

export default function RootLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	return (
		<html lang="en">
			<body>
				<header className="site-header">
					<a href="/" className="brand">
						go-secretbox
					</a>
					<nav>
						<a href="https://github.com/floatpane/go-secretbox">GitHub</a>
					</nav>
				</header>
				<main>{children}</main>
			</body>
		</html>
	);
}

export const viewport = { width: "device-width", initialScale: 1 };
