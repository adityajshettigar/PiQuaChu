'use client';

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Play, Pause } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

// --- Types & Interfaces ---
interface FluxNode {
    x: number;
    y: number;
    originX: number;
    originY: number;
    vx: number;
    vy: number;
    size: number;
    angle: number;
    speed: number;
}

export interface QuantumFluxProps {
    headline?: string;
    className?: string;
    density?: number;
}

export function QuantumFlux({
    className = "",
    density = 90,
}: QuantumFluxProps) {
    const containerRef = useRef<HTMLDivElement | null>(null);
    const canvasRef = useRef<HTMLCanvasElement | null>(null);

    const [isRunning, setIsRunning] = useState(true);

    // Inertial pointer state
    const pointerRef = useRef({
        x: -2000,
        y: -2000,
        targetX: -2000,
        targetY: -2000,
    });

    const nodesRef = useRef<FluxNode[]>([]);
    const dimensionsRef = useRef({ width: 0, height: 0 });

    // --- Initialize Quantum Field Nodes ---
    const initSystem = useCallback(() => {
        const { width, height } = dimensionsRef.current;
        if (width === 0 || height === 0) return;

        const nodes: FluxNode[] = [];
        const cols = Math.floor(Math.sqrt(density * (width / height)));
        const rows = Math.floor(density / cols);

        const cellWidth = width / (cols + 1);
        const cellHeight = height / (rows + 1);

        for (let i = 1; i <= cols; i++) {
            for (let j = 1; j <= rows; j++) {
                const x = i * cellWidth + (Math.random() - 0.5) * 20;
                const y = j * cellHeight + (Math.random() - 0.5) * 20;
                nodes.push({
                    x,
                    y,
                    originX: x,
                    originY: y,
                    vx: 0,
                    vy: 0,
                    size: Math.random() * 2 + 1,
                    angle: Math.random() * Math.PI * 2,
                    speed: Math.random() * 0.02 + 0.01,
                });
            }
        }
        nodesRef.current = nodes;
    }, [density]);

    // --- High-Performance Canvas Resize ---
    useEffect(() => {
        const container = containerRef.current;
        const canvas = canvasRef.current;
        if (!container || !canvas) return;

        const ctx = canvas.getContext('2d', { alpha: false });
        if (!ctx) return;

        const resizeObserver = new ResizeObserver((entries) => {
            for (const entry of entries) {
                const rect = entry.contentRect;
                const dpr = Math.min(window.devicePixelRatio || 1, 2);

                dimensionsRef.current = { width: rect.width, height: rect.height };
                canvas.width = Math.floor(rect.width * dpr);
                canvas.height = Math.floor(rect.height * dpr);
                canvas.style.width = `${rect.width}px`;
                canvas.style.height = `${rect.height}px`;

                ctx.setTransform(1, 0, 0, 1, 0, 0);
                ctx.scale(dpr, dpr);

                initSystem();
            }
        });

        resizeObserver.observe(container);
        return () => resizeObserver.disconnect();
    }, [initSystem]);

    // --- Main Smooth Render Loop ---
    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d', { alpha: false });
        if (!ctx) return;

        let animId = 0;

        const render = () => {
            if (!isRunning) {
                animId = requestAnimationFrame(render);
                return;
            }

            const { width, height } = dimensionsRef.current;
            const pointer = pointerRef.current;
            const nodes = nodesRef.current;

            // Silky smooth mouse interpolation (Lerp)
            pointer.x += (pointer.targetX - pointer.x) * 0.08;
            pointer.y += (pointer.targetY - pointer.y) * 0.08;

            // Deep space background with motion blur trailing
            ctx.fillStyle = 'var(--background)';
            ctx.fillRect(0, 0, width, height);

            // Dynamic volumetric cursor aura
            if (pointer.x > 0 && pointer.y > 0) {
                const glow = ctx.createRadialGradient(
                    pointer.x, pointer.y, 5,
                    pointer.x, pointer.y, 350
                );
                glow.addColorStop(0, 'rgba(255, 255, 255, 0.08)');
                glow.addColorStop(1, 'rgba(3, 3, 5, 0)');
                ctx.fillStyle = glow;
                ctx.fillRect(0, 0, width, height);
            }

            // Update and render node mesh
            ctx.lineWidth = 0.75;
            for (let i = 0; i < nodes.length; i++) {
                const node = nodes[i];

                // Orbital drift oscillation
                node.angle += node.speed;
                const targetX = node.originX + Math.cos(node.angle) * 15;
                const targetY = node.originY + Math.sin(node.angle) * 15;

                // Spring physics back to target
                const fx = (targetX - node.x) * 0.05;
                const fy = (targetY - node.y) * 0.05;

                node.vx = (node.vx + fx) * 0.85;
                node.vy = (node.vy + fy) * 0.85;

                node.x += node.vx;
                node.y += node.vy;

                // Mouse gravitational repulsion field
                const dx = pointer.x - node.x;
                const dy = pointer.y - node.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                const repelRadius = 160;

                if (dist < repelRadius && dist > 0) {
                    const force = Math.pow(1 - dist / repelRadius, 2) * 12;
                    node.x -= (dx / dist) * force;
                    node.y -= (dy / dist) * force;
                }

                // Render node point
                ctx.fillStyle = 'rgba(255, 255, 255, 0.75)';
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
                ctx.fill();

                // Connect adjacent nodes dynamically for web matrix effect
                for (let j = i + 1; j < nodes.length; j++) {
                    const other = nodes[j];
                    const distanceSq = Math.pow(node.x - other.x, 2) + Math.pow(node.y - other.y, 2);
                    
                    if (distanceSq < 8500) {
                        const alpha = (1 - Math.sqrt(distanceSq) / 92) * 0.2;
                        ctx.strokeStyle = `rgba(255, 255, 255, ${alpha})`;
                        ctx.beginPath();
                        ctx.moveTo(node.x, node.y);
                        ctx.lineTo(other.x, other.y);
                        ctx.stroke();
                    }
                }
            }

            animId = requestAnimationFrame(render);
        };

        animId = requestAnimationFrame(render);
        return () => cancelAnimationFrame(animId);
    }, [isRunning]);

    // --- Interactive Mouse Handlers ---
    const handlePointerMove = (e: React.MouseEvent<HTMLDivElement>) => {
        const container = containerRef.current;
        if (!container) return;
        const rect = container.getBoundingClientRect();
        pointerRef.current.targetX = e.clientX - rect.left;
        pointerRef.current.targetY = e.clientY - rect.top;
    };

    const handlePointerLeave = () => {
        pointerRef.current.targetX = -2000;
        pointerRef.current.targetY = -2000;
    };

    return (
        <div
            ref={containerRef}
            onMouseMove={handlePointerMove}
            onMouseLeave={handlePointerLeave}
            className={cn(
                "group relative flex h-full w-full select-none flex-col justify-between overflow-hidden bg-[var(--background)] transition-colors duration-700",
                className
            )}
        >
            <canvas
                ref={canvasRef}
                className="absolute inset-0 block h-full w-full cursor-crosshair"
            />

            <div className="relative z-20 flex h-full w-full flex-col justify-between p-6 md:p-10 pointer-events-none">
                {/* Header Controls */}
                <header className="flex w-full items-center justify-between font-mono text-[11px] text-[var(--muted-foreground)] pointer-events-auto">
                    <button
                        onClick={() => setIsRunning((prev) => !prev)}
                        className="flex items-center gap-1.5 rounded-[var(--radius-lg)] border border-[var(--border)] bg-[color-mix(in_oklch,var(--surface)_30%,transparent)] px-3.5 py-1.5 backdrop-blur-xl transition-all hover:bg-[color-mix(in_oklch,var(--surface)_40%,transparent)] text-[var(--foreground)]"
                    >
                        {isRunning ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
                        <span className="hidden sm:inline font-mono text-[10px] tracking-wider text-[var(--muted-foreground)]">
                            {isRunning ? 'PAUSE' : 'PLAY'}
                        </span>
                    </button>
                </header>

                {/* Typography Layer */}
                <main className="pointer-events-none flex flex-col items-center justify-center text-center">
                    
                                   </main>
            </div>
        </div>
    );
}

export default QuantumFlux;
