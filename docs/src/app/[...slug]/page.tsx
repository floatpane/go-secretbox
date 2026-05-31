import fs from "node:fs/promises";
import path from "node:path";
import remarkCallout from "@r4ai/remark-callout";
import matter from "gray-matter";
import { notFound } from "next/navigation";
import { MDXRemote } from "next-mdx-remote/rsc";
import rehypeHighlight from "rehype-highlight";
import remarkFrontmatter from "remark-frontmatter";
import remarkGfm from "remark-gfm";
import { Mermaid } from "@/components/Mermaid";
import { Sidebar } from "@/components/Sidebar";

const CONTENT = path.join(process.cwd(), "content");

async function load(slug: string[]) {
	const file = path.join(CONTENT, `${slug.join("/")}.mdx`);
	try {
		return matter(await fs.readFile(file, "utf8"));
	} catch {
		return null;
	}
}

// Extract the raw text inside a fenced code block from the MDX-rendered tree.
function codeText(node: unknown): string {
	if (typeof node === "string") return node;
	if (Array.isArray(node)) return node.map(codeText).join("");
	if (node && typeof node === "object" && "props" in node) {
		// biome-ignore lint/suspicious/noExplicitAny: walking the MDX element tree
		return codeText((node as any).props?.children);
	}
	return "";
}

// Intercept ```mermaid fences and render them as diagrams; everything else
// stays a normal highlighted <pre>.
const components = {
	// biome-ignore lint/suspicious/noExplicitAny: MDX component props are untyped
	pre: (props: any) => {
		const child = props.children;
		const className: string = child?.props?.className ?? "";
		if (className.includes("language-mermaid")) {
			return <Mermaid chart={codeText(child.props.children).trim()} />;
		}
		return <pre {...props} />;
	},
};

export default async function DocPage({
	params,
}: {
	params: Promise<{ slug: string[] }>;
}) {
	const { slug } = await params;
	const doc = await load(slug);
	if (!doc) notFound();

	return (
		<div className="docs-layout">
			<aside className="docs-sidebar">
				<Sidebar />
			</aside>
			<article className="docs-content">
				<MDXRemote
					source={doc.content}
					components={components}
					options={{
						mdxOptions: {
							remarkPlugins: [remarkFrontmatter, remarkGfm, remarkCallout],
							rehypePlugins: [[rehypeHighlight, { ignoreMissing: true }]],
						},
					}}
				/>
			</article>
		</div>
	);
}
