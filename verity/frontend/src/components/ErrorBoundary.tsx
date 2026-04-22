import React from 'react'

interface State {
  error: Error | null
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  State
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-white px-8">
          <div className="max-w-lg text-center space-y-4">
            <h1 className="font-display font-bold text-2xl text-[#464646]">
              Something went wrong
            </h1>
            <pre className="text-left text-xs bg-gray-50 border border-[#e5e7eb] rounded-lg p-4 overflow-auto text-[#dc2626]">
              {this.state.error.message}
            </pre>
            <button
              onClick={() => {
                this.setState({ error: null })
                window.location.href = '/'
              }}
              className="text-sm text-[#1c9770] font-semibold hover:underline"
            >
              ← Back to Dashboard
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
