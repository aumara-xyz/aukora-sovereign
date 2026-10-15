// SPDX-License-Identifier: AGPL-3.0-or-later
import geometry from "../crates/pentora/vectors/geometry_index_table_v1.json" with { type: "json" };
import { hex, refuse } from "./bytes.ts";

export function drawRelationshipBloom(canvas: HTMLCanvasElement, digest: Uint8Array): void {
  if (digest.length !== 32) refuse("bloom-digest");
  const context = canvas.getContext("2d");
  if (!context) refuse("canvas");
  canvas.width = canvas.height = 600;
  context.fillStyle = "#07131e"; context.fillRect(0, 0, 600, 600);
  const phi = (1 + Math.sqrt(5)) / 2;
  const points = geometry.points.map(point => {
    const [x, y, z] = point.coordinates.map(value => value.a[0] / value.a[1] + value.b[0] / value.b[1] * phi);
    return { index: point.global_index, x: 300 + 118 * (x + 0.31 * z), y: 300 + 118 * (y - 0.27 * z), z };
  });
  const indexed = new Map(points.map(point => [point.index, point]));
  const colours = ["#6096a8", "#719cb4", "#6bafa8", "#9c9bb7", "#a9aa82"];
  geometry.cubes.forEach((cube, index) => {
    context.strokeStyle = colours[index]; context.lineWidth = 1.2;
    for (const [a, b] of cube.edges_global_indices) {
      const from = indexed.get(a), to = indexed.get(b);
      if (!from || !to) refuse("bloom-geometry");
      context.beginPath(); context.moveTo(from.x, from.y); context.lineTo(to.x, to.y); context.stroke();
    }
  });
  // These digest trits colour a relationship bloom, never a health map.
  let number = BigInt(`0x${hex(digest)}`);
  const trits = new Map<number, number>();
  for (let index = 0; index < 111; ++index) {
    if (index === geometry.centre_index) continue;
    trits.set(index, Number(number % 3n)); number /= 3n;
  }
  for (const point of [...points].sort((a, b) => a.z - b.z)) {
    const trit = trits.get(point.index);
    context.fillStyle = trit === undefined ? "#07131e" : ["#1c3b50", "#4cacc5", "#c1f4e6"][trit];
    context.beginPath(); context.arc(point.x, point.y, point.index === geometry.centre_index ? 3 : 5.5, 0, Math.PI * 2); context.fill();
  }
  canvas.setAttribute("aria-label", `Relationship bloom ${hex(digest)}`);
}
