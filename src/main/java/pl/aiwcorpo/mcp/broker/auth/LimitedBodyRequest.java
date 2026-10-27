package pl.aiwcorpo.mcp.broker.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Caps the bytes actually read from the body. Content-Length alone is not enough: a chunked body has
 * none, and without this cap it would be read and parsed whole.
 */
final class LimitedBodyRequest extends HttpServletRequestWrapper {

    static final class BodyTooLargeException extends IOException {

        BodyTooLargeException() {
            super("request body exceeds the limit");
        }
    }

    private final long limit;
    private ServletInputStream stream;

    LimitedBodyRequest(HttpServletRequest request, long limit) {
        super(request);
        this.limit = limit;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (stream == null) {
            stream = new Limited(super.getInputStream(), limit);
        }
        return stream;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        String encoding = getCharacterEncoding();
        return new BufferedReader(new InputStreamReader(getInputStream(),
                encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding)));
    }

    private static final class Limited extends ServletInputStream {

        private final ServletInputStream delegate;
        private final long limit;
        private long read;

        Limited(ServletInputStream delegate, long limit) {
            this.delegate = delegate;
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b >= 0) {
                count(1);
            }
            return b;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int n = delegate.read(buffer, offset, length);
            if (n > 0) {
                count(n);
            }
            return n;
        }

        private void count(int n) throws IOException {
            read += n;
            if (read > limit) {
                throw new BodyTooLargeException();
            }
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            delegate.setReadListener(listener);
        }
    }
}
