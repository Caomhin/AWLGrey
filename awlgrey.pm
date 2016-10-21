# <@LICENSE>
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Plugin::AWLGrey - Detect first time senders via auto-whitelist

=head1 SYNOPSIS

To try this out, add this to a local .cf file:

loadplugin	Mail::SpamAssassin::Plugin::AWLGrey awlgrey.pm

ifplugin	Mail::SpamAssassin::Plugin::AWL
ifplugin	Mail::SpamAssassin::Plugin::AWLGrey
  header	__AWLGREY	eval:check_auto_whitelist_unknown()
  describe	__AWLGREY	From: address is unknown in the auto white-list
  priority	__AWLGREY	100 # Must be run before AWL (default 1000)
endif
endif

=head1 DESCRIPTION

This plugin module uses the auto-whitelist database to detect unknown senders.  
The result is a purely informational flag which can be used in meta rules where 
traits from unknown users are far more suspicious.

=head1 TEMPLATE TAGS

This plugin module adds the following C<tags> that can be used as
placeholders in certain options.  See C<Mail::SpamAssassin::Conf>
for more information on TEMPLATE TAGS.

 _AWLGREY_             AWLGrey result status

=cut

package Mail::SpamAssassin::Plugin::AWLGrey;

use strict;
use warnings;
use bytes;
use re 'taint';
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::AutoWhitelist;
use Mail::SpamAssassin::Logger;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_auto_whitelist_unknown");

  return $self;
}

sub check_auto_whitelist_unknown {
    dbg("awlgrey: Starting check");
		my ($self, $pms) = @_;

    return 0 unless ($pms->{conf}->{use_auto_whitelist});

    my $from = lc $pms->get('From:addr');
    dbg("awlgrey: From: $from");
    return 0 unless $from =~ /\S/;

    # find the earliest usable "originating IP".  ignore private nets
    my $origip;
    foreach my $rly (reverse (@{$pms->{relays_trusted}}, @{$pms->{relays_untrusted}}))
    {
      next if ($rly->{ip_private});
      if ($rly->{ip}) {
	$origip = $rly->{ip}; last;
      }
    }
		dbg("awlgrey: IP: %s", $origip || 'undef');

    my $signedby = $pms->get_tag('DKIMDOMAIN');
    undef $signedby  if defined $signedby && $signedby eq '';

   # Create an AWL object
    my $awl;
    eval {
      $awl = Mail::SpamAssassin::AutoWhitelist->new($pms->{main});

      my $trigger = $awl->check_address($from, $origip, $signedby);
      my $count = $awl->count();
      dbg("awlgrey: %s hits", $count);

      dbg("awlgrey: AWLGrey active, previous sightings: %s, IP: %s, address: %s %s",
          $count, $origip || 'undef', $from,
          $signedby ? "signed by $signedby" : '(not signed)');
		  
      $pms->set_tag('AWLGREY',  sprintf("%d sightings", $count));

      my $unseen = $count ? 0 : 1;
      return $unseen;
    };
}

1;

=back

=cut
