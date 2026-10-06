import type { Metadata } from "next";
import { ScanModePage } from "@/components/ScanModePage";

export const metadata: Metadata = { title: "Quét cơ bản" };
export const dynamic = "force-dynamic";

export default async function Page({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan } = await searchParams;
  return <ScanModePage kind="basic" prefill={scan} />;
}
