"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

const SECTIONS = [
	{ title: "Introduction", slug: "introduction" },
	{ title: "Getting Started", slug: "getting-started" },
	{ title: "One-Shot: Seal & Unseal", slug: "seal" },
	{ title: "The Vault", slug: "vault" },
	{ title: "Key Rotation", slug: "rotation" },
	{ title: "Threat Model", slug: "security" },
];

export function Sidebar() {
	const [open, setOpen] = useState(false);
	const pathname = usePathname();
	return (
		<nav className="sidebar-nav" data-open={open}>
			<button
				type="button"
				className="sidebar-toggle"
				aria-expanded={open}
				aria-controls="sidebar-list"
				onClick={() => setOpen((v) => !v)}
			>
				<span>Documentation</span>
				<span className="sidebar-toggle-icon" aria-hidden="true">
					{open ? "✕" : "☰"}
				</span>
			</button>
			<ul id="sidebar-list">
				{SECTIONS.map((s) => {
					const href = `/${s.slug}`;
					return (
						<li key={s.slug}>
							<Link
								href={href}
								aria-current={pathname === href ? "page" : undefined}
								onClick={() => setOpen(false)}
							>
								{s.title}
							</Link>
						</li>
					);
				})}
			</ul>
		</nav>
	);
}
