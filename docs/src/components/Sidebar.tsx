import Link from "next/link";

const SECTIONS = [
	{ title: "Introduction", slug: "introduction" },
	{ title: "Getting Started", slug: "getting-started" },
	{ title: "One-Shot: Seal & Unseal", slug: "seal" },
	{ title: "The Vault", slug: "vault" },
	{ title: "Key Rotation", slug: "rotation" },
	{ title: "Threat Model", slug: "security" },
];

export function Sidebar() {
	return (
		<nav>
			<ul>
				{SECTIONS.map((s) => (
					<li key={s.slug}>
						<Link href={`/${s.slug}`}>{s.title}</Link>
					</li>
				))}
			</ul>
		</nav>
	);
}
