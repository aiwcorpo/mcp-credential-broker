package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;

import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;

/** The switch of a connection to a rotated credential when the answer of the database is lost. */
class ConnectionStoreRefreshTest {

    private final List<String> deleted = new ArrayList<>();
    private final List<String> written = new ArrayList<>();
    private final AtomicReference<String> rowVersion = new AtomicReference<>("v1");
    private final ConnectionRepository repository = mock(ConnectionRepository.class);

    private final SecretStore secrets = new SecretStore() {
        @Override
        public void put(SecretKey key, StoredCredential credential) {
            written.add(key.version());
        }

        @Override
        public Optional<StoredCredential> get(SecretKey key) {
            return Optional.empty();
        }

        @Override
        public void delete(SecretKey key) {
            deleted.add(key.version());
        }

        @Override
        public void deleteAllOf(String sub) {
        }
    };

    private final Connection current = new Connection("s", "gitlab", CredentialType.USER_OAUTH, Connection.StoredState.CONNECTED,
            "u", null, Instant.now(), null, "v1", Instant.now());
    private final StoredCredential rotated = new StoredCredential(CredentialType.USER_OAUTH, SecretValue.of("a"), SecretValue.of("r"));

    private ConnectionStore store() {
        return new ConnectionStore(repository, secrets, mock(InvalidationPublisher.class), Clock.systemUTC(), new long[] {1, 1});
    }

    private Connection rowNow() {
        return current.withSecretVersion(rowVersion.get());
    }

    @Test
    void anUpdateCommittedWithItsAnswerLostCountsAsSaved() {
        when(repository.switchSecretVersion(any(), any(), any(), any(), any(), any())).thenAnswer(call -> {
            if (rowVersion.get().equals("v1")) {
                rowVersion.set(call.getArgument(3));
                throw new QueryTimeoutException("answer lost");
            }
            return rowVersion.get().equals(call.getArgument(2));
        });
        when(repository.find("s", "gitlab")).thenAnswer(call -> Optional.of(rowNow()));

        Optional<Connection> saved = store().refresh(current, rotated, Instant.now());

        assertThat(saved).isPresent();
        assertThat(saved.get().secretVersion()).isEqualTo(rowVersion.get()).isNotEqualTo("v1");
        assertThat(deleted).as("only the previous version goes").doesNotContain(rowVersion.get());
    }

    @Test
    void whenTheRowCannotBeReadNothingIsDeletedAndTheOutcomeIsUnknown() {
        when(repository.switchSecretVersion(any(), any(), any(), any(), any(), any())).thenThrow(new QueryTimeoutException("lost"));
        when(repository.find("s", "gitlab")).thenThrow(new QueryTimeoutException("still down"));

        assertThatThrownBy(() -> store().refresh(current, rotated, Instant.now())).isInstanceOf(RefreshOutcomeUnknownException.class);
        assertThat(deleted).isEmpty();
    }

    @Test
    void anUpdateThatDidNotHappenRemovesTheNewVersionAndRethrows() {
        QueryTimeoutException failure = new QueryTimeoutException("down");
        when(repository.switchSecretVersion(any(), any(), any(), any(), any(), any())).thenThrow(failure);
        when(repository.find("s", "gitlab")).thenAnswer(call -> Optional.of(rowNow()));

        assertThatThrownBy(() -> store().refresh(current, rotated, Instant.now())).isSameAs(failure);
        assertThat(deleted).containsExactlyElementsOf(written);
    }

    @Test
    void aRowReplacedMeanwhileRemovesTheNewVersionAndReportsNothingSaved() {
        when(repository.switchSecretVersion(any(), any(), any(), any(), any(), any())).thenReturn(false);
        rowVersion.set("v-other");
        when(repository.find("s", "gitlab")).thenAnswer(call -> Optional.of(rowNow()));

        assertThat(store().refresh(current, rotated, Instant.now())).isEmpty();
        assertThat(deleted).containsExactlyElementsOf(written);
    }
}
