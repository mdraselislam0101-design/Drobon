import { Link } from 'react-router-dom';

export function NotFoundPage(): React.JSX.Element {
  return (
    <section className="panel" aria-labelledby="missing-title">
      <p className="eyebrow">404</p>
      <h1 id="missing-title">Page not found.</h1>
      <p className="lede">The page you asked for does not exist or moved.</p>
      <Link className="button" to="/">
        Back to home
      </Link>
    </section>
  );
}
