import React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 rounded-lg font-display font-bold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1c9770] focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default:
          'bg-[#1c9770] text-white hover:bg-[#177a5a] active:bg-[#145f47]',
        outline:
          'border border-[#1c9770] text-[#1c9770] bg-transparent hover:bg-[#bef3e2] active:bg-[#a8e8d2]',
        ghost:
          'text-[#464646] bg-transparent hover:bg-gray-100 active:bg-gray-200',
        destructive:
          'bg-[#dc2626] text-white hover:bg-[#b91c1c] active:bg-[#991b1b]',
      },
      size: {
        sm: 'px-3 py-1.5 text-sm',
        md: 'px-4 py-2 text-sm',
        lg: 'px-6 py-3 text-base',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'md',
    },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      />
    )
  },
)

Button.displayName = 'Button'

export { Button, buttonVariants }
